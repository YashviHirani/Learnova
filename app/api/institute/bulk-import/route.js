import { NextResponse } from "next/server";
import { initFirebaseAdmin, getAdminDb } from "@/lib/firebase-admin";
import { parseJSON } from "@/lib/error-handler";
import admin from "firebase-admin";
import { connectDb } from "@/lib/mongodb";
import { checkRateLimit } from "@/lib/rateLimit";
import { requireRole } from "@/lib/rbac";
import crypto from "crypto";

export const dynamic = "force-dynamic";

const MAX_BULK_IMPORT_PAYLOAD_BYTES = 1024 * 1024;

export async function POST(req) {
  try {
    // Authenticate and authorize — only institute or admin can bulk-import
    const { payload: decodedToken } = await requireRole(req, ["institute", "admin"]);

    const ip = req.headers.get("x-forwarded-for") || "127.0.0.1";
    const rateLimitResult = await checkRateLimit(`bulk_import_${ip}_${decodedToken.uid}`);
    if (!rateLimitResult.allowed) {
      return NextResponse.json(
        { error: "Too many requests. Please try again later." },
        { status: 429 }
      );
    }

    const body = await parseJSON(req, MAX_BULK_IMPORT_PAYLOAD_BYTES);
    const { students } = body;

    if (!students || !Array.isArray(students)) {
      return NextResponse.json(
        { error: "Invalid data format. Expected an array of students." },
        { status: 400 }
      );
    }

    // Initialize Firebase Admin
    initFirebaseAdmin();
    const firestore = getAdminDb();
    
    // Connect to MongoDB
    const mongoDb = await connectDb();
    const mongoUsers = mongoDb.collection("users");

    let successfulImports = 0;
    const failedImports = [];

    // Process students sequentially or in parallel batches
    for (const student of students) {
      const { name, email, rollNo, department } = student;
      const password = crypto.randomUUID();

      try {
        // 1. Create Firebase Auth user
        let userRecord;
        let userAlreadyExisted = false;
        try {
          userRecord = await admin.auth().getUserByEmail(email);
          userAlreadyExisted = true;
        } catch (error) {
          if (error.code === 'auth/user-not-found') {
            userRecord = await admin.auth().createUser({
              email: email,
              password: password,
              displayName: name,
              emailVerified: true,
            });
          } else {
            throw error;
          }
        }

        // 2. Persist to Firestore (used by dashboard and auth checks)
        try {
          await firestore.collection("users").doc(userRecord.uid).set({
            fullName: name,
            email: email,
            role: "student",
            rollNo: rollNo,
            department: department,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            isBulkImported: true,
          }, { merge: true });
        } catch (firestoreErr) {
          // Roll back Firebase Auth user if we just created it
          if (!userAlreadyExisted) {
            try { await admin.auth().deleteUser(userRecord.uid); } catch {}
          }
          throw firestoreErr;
        }

        // 3. Persist to MongoDB (used by face recognition system)
        // Check if user exists in Mongo
        const existingMongoUser = await mongoUsers.findOne({
          $or: [{ email }, { rollNo }],
        });

        if (!existingMongoUser) {
          try {
            await mongoUsers.insertOne({
              name,
              rollNo,
              email,
              department,
              firebaseUid: userRecord.uid,
              isBulkImported: true,
              createdAt: new Date(),
            });
          } catch (mongoErr) {
            // Roll back Firestore and Firebase Auth if we just created them
            if (!userAlreadyExisted) {
              try {
                await firestore.collection("users").doc(userRecord.uid).delete();
                await admin.auth().deleteUser(userRecord.uid);
              } catch {}
            }
            throw mongoErr;
          }
        }

        successfulImports++;
      } catch (err) {
        failedImports.push({
          email,
          rollNo,
          reason: err.message,
        });
      }
    }

    return NextResponse.json({
      success: true,
      successfulImports,
      failedImports,
    }, { status: 200 });

  } catch (error) {
    if (error.statusCode) {
      return NextResponse.json(
        { error: error.message },
        { status: error.statusCode }
      );
    }

    console.error("Bulk import error:", error);
    return NextResponse.json(
      { error: error.message || "Internal server error" },
      { status: 500 }
    );
  }
}
