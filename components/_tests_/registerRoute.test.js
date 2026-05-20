import { POST } from "@/app/api/register/route";
import { connectDb } from "@/lib/mongodb";
import { put } from "@vercel/blob";

jest.mock("next/server", () => ({
  NextResponse: {
    json: jest.fn().mockImplementation((body, init) => {
      return {
        status: init?.status || 200,
        json: async () => body,
        headers: new Map(),
      };
    }),
  },
}));

jest.mock("@vercel/blob", () => ({
  put: jest.fn(),
}));

jest.mock("@/lib/mongodb", () => ({
  connectDb: jest.fn(),
}));

describe("POST /api/register - Security & Validation Tests", () => {
  let mockFindOne;
  let mockInsertOne;

  beforeEach(() => {
    jest.clearAllMocks();

    mockFindOne = jest.fn();
    mockInsertOne = jest.fn();

    connectDb.mockResolvedValue({
      collection: jest.fn().mockReturnValue({
        findOne: mockFindOne,
        insertOne: mockInsertOne,
      }),
    });

    put.mockResolvedValue({ url: "https://example.com/blob.jpg" });
  });

  const createMockFile = (mimeType, size, magicBytes = []) => {
    const buffer = new Uint8Array(magicBytes.concat(new Array(Math.max(0, 12 - magicBytes.length)).fill(0))).buffer;
    const mockFileObj = {
      type: mimeType,
      size: size,
      arrayBuffer: jest.fn().mockResolvedValue(buffer),
      slice: jest.fn().mockReturnValue({
        arrayBuffer: jest.fn().mockResolvedValue(buffer),
      }),
    };
    return mockFileObj;
  };

  const mockFile = createMockFile("image/jpeg", 1024, [0xff, 0xd8, 0xff]);

  const createMockRequest = (data) => {
    return {
      formData: jest.fn().mockResolvedValue({
        get: (key) => data[key],
      }),
    };
  };

  test("accepts valid email and registers user successfully", async () => {
    mockFindOne.mockResolvedValue(null);
    mockInsertOne.mockResolvedValue({ insertedId: "mock-id" });

    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user+tag@domain.co.uk",
      photo: mockFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(body.data.user.email).toBe("user+tag@domain.co.uk");
    expect(mockInsertOne).toHaveBeenCalled();
  });

  test.each([
    ["invalid-email"],
    ["test@domain"],
    ["@domain.com"],
    ["user@domain."],
    ["user @domain.com"],
    ["user@ domain.com"],
  ])("rejects invalid email format '%s' with 400 Bad Request", async (invalidEmail) => {
    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: invalidEmail,
      photo: mockFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error).toBe("Invalid email address");
    expect(mockInsertOne).not.toHaveBeenCalled();
    expect(connectDb).not.toHaveBeenCalled(); // Validation must happen before DB connection or insertion
  });

  test("rejects request if file size exceeds MAX_FILE_SIZE (5MB)", async () => {
    const oversizedFile = {
      ...mockFile,
      size: 6 * 1024 * 1024, // 6MB
    };

    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user@domain.com",
      photo: oversizedFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(413);
    expect(body.error).toContain("File too large");
    expect(mockInsertOne).not.toHaveBeenCalled();
    expect(connectDb).not.toHaveBeenCalled(); // Validation must happen before DB connection or insertion
  });

  test("accepts request if file size is exactly at the limit (5MB)", async () => {
    mockFindOne.mockResolvedValue(null);
    mockInsertOne.mockResolvedValue({ insertedId: "mock-id" });

    const limitFile = {
      ...mockFile,
      size: 5 * 1024 * 1024, // 5MB
    };

    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user@domain.com",
      photo: limitFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
    expect(mockInsertOne).toHaveBeenCalled();
  });

  test("accepts valid PNG image upload successfully", async () => {
    mockFindOne.mockResolvedValue(null);
    mockInsertOne.mockResolvedValue({ insertedId: "mock-id" });

    const pngFile = createMockFile("image/png", 2048, [0x89, 0x50, 0x4e, 0x47]);

    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user@domain.com",
      photo: pngFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
  });

  test("accepts valid WebP image upload successfully", async () => {
    mockFindOne.mockResolvedValue(null);
    mockInsertOne.mockResolvedValue({ insertedId: "mock-id" });

    const webpFile = createMockFile("image/webp", 2048, [
      0x52, 0x49, 0x46, 0x46, // "RIFF"
      0, 0, 0, 0,
      0x57, 0x45, 0x42, 0x50  // "WEBP"
    ]);

    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user@domain.com",
      photo: webpFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(201);
    expect(body.success).toBe(true);
  });

  test("rejects request if file is not a valid File object (e.g. string)", async () => {
    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user@domain.com",
      photo: "not-a-file-object",
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error).toContain("must be a valid image file");
    expect(mockInsertOne).not.toHaveBeenCalled();
  });

  test("rejects request if MIME type is not allowed (e.g. application/zip)", async () => {
    const zipFile = createMockFile("application/zip", 1024, [0x50, 0x4b, 0x03, 0x04]);

    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user@domain.com",
      photo: zipFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error).toContain("Only JPEG, PNG, and WebP images are allowed");
    expect(mockInsertOne).not.toHaveBeenCalled();
  });

  test("rejects request if MIME type is spoofed (e.g. EXE file named as PNG)", async () => {
    const exeFile = createMockFile("image/png", 1024, [0x4d, 0x5a]);

    const req = createMockRequest({
      name: "John Doe",
      rollNo: "123456",
      email: "user@domain.com",
      photo: exeFile,
    });

    const response = await POST(req);
    const body = await response.json();

    expect(response.status).toBe(400);
    expect(body.error).toContain("headers do not match the expected image format");
    expect(mockInsertOne).not.toHaveBeenCalled();
  });
});
