import express from "express";
import cors from "cors";
import morgan from "morgan";
import multer from "multer";
import crypto from "crypto";
import fetch from "node-fetch";
import sharp from "sharp";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const s3 = new S3Client({
  region: process.env.S3_REGION,
  endpoint: process.env.S3_ENDPOINT,
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  },
});

const app = express();
app.use(morgan("dev"));

app.post("/api/shopify/order-paid", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const body = req.body.toString("utf8");
    const order = JSON.parse(body);
// Prevent double-processing if multiple webhooks hit for the same order
const orderId = order.id;

global.__processedOrders = global.__processedOrders || new Set();

if (global.__processedOrders.has(orderId)) {
  console.log("Already processed order, skipping:", orderId);
  return res.status(200).send("ok");
}

global.__processedOrders.add(orderId);

    console.log("ORDER WEBHOOK RECEIVED");
    const lineItems = order.line_items || [];

// STEP B: Only process real printed-fabric items

function propsArrayToObject(properties) {
  const obj = {};
  for (const p of properties || []) {
    if (!p) continue;
    const name = p.name ?? p.key;
    const value = p.value;
    if (name != null) obj[String(name)] = value;
  }
  return obj;
}

const printableItems = lineItems
  .map((item) => ({ item, props: propsArrayToObject(item.properties) }))
  .filter(({ props }) => props.upload_url || props.upload_id);

console.log(`Line items: ${lineItems.length} | Printable items: ${printableItems.length}`);

for (const { item, props } of printableItems) {
  console.log("PROCESSING PRINT ITEM:", item.title);
  console.log({
    upload_url: props.upload_url,
    dpi: props.dpi,
    tile_w: props.tile_w,
    tile_h: props.tile_h,
    rotate: props.rotate,
    max_width_in: props.max_width_in,
    qty: props.qty,
  });
// STEP C.2 — Download the uploaded image and log its size
const uploadUrl = props.upload_url;

console.log("Downloading image:", uploadUrl);

const imgRes = await fetch(uploadUrl);
if (!imgRes.ok) {
  throw new Error(`Image download failed: ${imgRes.status} ${imgRes.statusText}`);
}

const imgBuf = Buffer.from(await imgRes.arrayBuffer());

console.log("Downloaded image size (bytes):", imgBuf.length);
// STEP C.3 — Read image metadata (sanity check)
const meta = await sharp(imgBuf, { failOn: "none" }).metadata();
console.log("Image metadata:", {
  format: meta.format,
  width: meta.width,
  height: meta.height
});
// STEP C.4 — Build the scaled tile at 300 DPI
const tileWIn = parseFloat(props.tile_w);
const tileHIn = parseFloat(props.tile_h);
const dpi = parseInt(props.dpi || "300", 10);

const tileWpx = Math.round(tileWIn * dpi);
const tileHpx = Math.round(tileHIn * dpi);

console.log("Tile target (px):", tileWpx, tileHpx);

const tileBuf = await sharp(imgBuf)
  .resize(tileWpx, tileHpx, { fit: "cover" })
  .toBuffer();

console.log("Tile buffer size (bytes):", tileBuf.length);
 

// STEP C.5 — Repeat tile across fabric width (one row)
const maxWidthIn = parseFloat(props.max_width_in);
const fabricWidthPx = Math.round(maxWidthIn * dpi);

console.log("Fabric width (px):", fabricWidthPx);

// how many tiles fit across
const tilesAcross = Math.ceil(fabricWidthPx / tileWpx);
console.log("Tiles across:", tilesAcross);
  
// STEP C.6 — Build a small "row preview" (safe)
const previewTilesAcross = Math.min(tilesAcross, 8); // cap to avoid OOM
const previewWidthPx = previewTilesAcross * tileWpx;

console.log("Preview tiles across:", previewTilesAcross);
console.log("Preview width (px):", previewWidthPx);

const previewRowBuf = await sharp({
  create: {
    width: previewWidthPx,
    height: tileHpx,
    channels: 4,
    background: { r: 255, g: 255, b: 255, alpha: 0 }
  }
})
  .composite(
    Array.from({ length: previewTilesAcross }).map((_, i) => ({
      input: tileBuf,
      left: i * tileWpx,
      top: 0
    }))
  )
  .png()
  .toBuffer();

console.log("Preview row buffer size (bytes):", previewRowBuf.length);
// STEP C.7 — Export print-ready TIFF (tile only)
const tiffBuf = await sharp(tileBuf)
  .tiff({
    compression: "lzw",
    xres: dpi,
    yres: dpi,
    resolutionUnit: "inch"
  })
  .toBuffer();

console.log("TIFF buffer size (bytes):", tiffBuf.length);
// Upload TIFF tile to R2
const lineId = item.id || item.variant_id || "line";
const tiffKey = s3KeyForOutput(orderId, lineId, "tile");
const tiffUrl = await putPublicObject(tiffKey, "image/tiff", tiffBuf);

console.log("TIFF uploaded:", tiffUrl);

continue; // stop here for now; avoid huge fabric build until tile upload is confirmed

// build composite operations
const composites = [];
for (let x = 0; x < tilesAcross; x++) {
  composites.push({
    input: tileBuf,
    left: x * tileWpx,
    top: 0
  });
}

const rowBuf = await sharp({
  create: {
    width: fabricWidthPx,
    height: tileHpx,
    channels: 4,
    background: { r: 255, g: 255, b: 255, alpha: 0 }
  }
})
  .composite(composites)
  .png()
  .toBuffer();

console.log("Row buffer size (bytes):", rowBuf.length);
// STEP C.6 — Stack rows to full fabric height
const yards = parseInt(props.qty || "1", 10);
const fabricHeightIn = yards * 36;
const fabricHeightPx = Math.round(fabricHeightIn * dpi);

console.log("Fabric height (px):", fabricHeightPx);

// how many rows needed
const rowsDown = Math.ceil(fabricHeightPx / tileHpx);
console.log("Rows down:", rowsDown);

// build vertical composites
const rowComposites = [];
for (let y = 0; y < rowsDown; y++) {
  rowComposites.push({
    input: rowBuf,
    left: 0,
    top: y * tileHpx
  });
}

const fabricBuf = await sharp({
  create: {
    width: fabricWidthPx,
    height: fabricHeightPx,
    channels: 4,
    background: { r: 255, g: 255, b: 255, alpha: 0 }
  }
})
  .composite(rowComposites)
  .png()
  .toBuffer();

console.log("Final fabric buffer size (bytes):", fabricBuf.length);

  // Step C (TIFF generator) will go here next
}


    res.status(200).send("OK");
  } catch (err) {
    console.error("Webhook error:", err);
    res.status(500).send("Webhook error");
  }
});

app.use(express.json({ type: ["application/json"] }));
app.use(cors({ origin: true }));

app.get("/api/health", (req, res) => {
  res.status(200).json({ ok: true, ts: Date.now() });
});

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 40 * 1024 * 1024 } }); // 40MB

const {
  PORT = "8080",
  SHOPIFY_WEBHOOK_SECRET,

  S3_REGION,
  S3_ENDPOINT,
  S3_BUCKET,
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  S3_PUBLIC_BASE,

  OUTPUT_DPI = "300",
  FABRIC_WIDTH_IN = "54",

  ADMIN_USER,
  ADMIN_PASS
} = process.env;

const jobs = new Map(); // upload_id -> { upload_url, created_at, outputs: {tile, full_width, order_id, line_id} }

function basicAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) return next();
  const hdr = req.headers.authorization || "";
  const [type, token] = hdr.split(" ");
  if (type !== "Basic" || !token) return res.status(401).set("WWW-Authenticate", "Basic").send("Auth required");
  const [u, p] = Buffer.from(token, "base64").toString("utf8").split(":");
  if (u !== ADMIN_USER || p !== ADMIN_PASS) return res.status(403).send("Forbidden");
  next();
}

function s3KeyForUpload(uploadId, filename) {
  const safe = filename.replace(/[^\w.\-() ]+/g, "_");
  return `uploads/${uploadId}/${safe}`;
}
function s3KeyForOutput(orderId, lineId, kind) {
  return `outputs/order_${orderId}/line_${lineId}/${kind}.tiff`;
}

async function putPublicObject(key, contentType, bodyBuffer) {
  const cmd = new PutObjectCommand({
    Bucket: S3_BUCKET,
    Key: key,
    Body: bodyBuffer,
    ContentType: contentType
  });
  await s3.send(cmd);
  return `${S3_PUBLIC_BASE.replace(/\/$/,"")}/${key}`;
}

function verifyShopifyWebhook(rawBody, hmacHeader) {
  if (!SHOPIFY_WEBHOOK_SECRET) return false;
  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody, "utf8")
    .digest("base64");
  try {
    return crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(hmacHeader || ""));
  } catch {
    return false;
  }
}

app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "missing_file" });
    const uploadId = crypto.randomBytes(12).toString("hex");
    const key = s3KeyForUpload(uploadId, req.file.originalname);
    const uploadUrl = await putPublicObject(key, req.file.mimetype || "application/octet-stream", req.file.buffer);
    jobs.set(uploadId, { upload_url: uploadUrl, created_at: Date.now(), outputs: {} });
    res.json({ upload_id: uploadId, upload_url: uploadUrl });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "upload_failed" });
  }
});

function getProp(lineItem, name) {
  const props = lineItem.properties || [];
  const hit = props.find(p => (p.name || p.key) === name);
  return hit ? (hit.value ?? "") : "";
}
function parseInches(str) {
  if (!str) return null;
  const v = String(str).replace(/"/g,"").trim();
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

app.post("/webhooks/orders-create", express.raw({ type: "*/*" }), async (req, res) => {
  try {
    const hmac = req.headers["x-shopify-hmac-sha256"];
    const raw = req.body.toString("utf8");
    if (!verifyShopifyWebhook(raw, hmac)) return res.status(401).send("Invalid HMAC");

    const order = JSON.parse(raw);
    const orderId = order.id;

    for (const li of (order.line_items || [])) {
      const uploadUrl = getProp(li, "Scale Tool - Upload URL");
      const output = (getProp(li, "Scale Tool - Output") || "tile").toLowerCase();
      const tileWidthIn =
        parseInches(getProp(li, "Scale Tool - Tile Width (in)")) ||
        parseInches(getProp(li, "Scale Tool - Target Repeat Width (in)"));

      if (!uploadUrl || !tileWidthIn) continue;

      const outDpi = Number(OUTPUT_DPI) || 300;
      const fabricWidthIn = Number(FABRIC_WIDTH_IN) || 54;

      const imgRes = await fetch(uploadUrl);
      if (!imgRes.ok) throw new Error(`Failed to fetch upload_url: ${uploadUrl}`);
      const imgBuf = Buffer.from(await imgRes.arrayBuffer());

      const tileWpx = Math.max(1, Math.round(tileWidthIn * outDpi));
      const meta = await sharp(imgBuf).metadata();
      const aspect = (meta.height && meta.width) ? (meta.height / meta.width) : 1;
      const tileHpx = Math.max(1, Math.round(tileWpx * aspect));

      const tileTiff = await sharp(imgBuf)
        .resize(tileWpx, tileHpx, { fit: "fill" })
        .tiff({ compression: "lzw" })
        .toBuffer();

      const fullWpx = Math.max(1, Math.round(fabricWidthIn * outDpi));
      const fullHpx = tileHpx;

      const tilesAcross = Math.ceil(fullWpx / tileWpx);
      const composites = [];
      for (let i = 0; i < tilesAcross; i++) {
        composites.push({ input: tileTiff, left: i * tileWpx, top: 0 });
      }

      const fullTiff = await sharp({
        create: {
          width: fullWpx,
          height: fullHpx,
          channels: 4,
          background: { r: 255, g: 255, b: 255, alpha: 1 }
        }
      })
        .composite(composites)
        .tiff({ compression: "lzw" })
        .toBuffer();

      const lineId = li.id || li.variant_id || "line";
      let tileUrl = null, fullUrl = null;

      if (output === "tile" || output === "both") {
        tileUrl = await putPublicObject(s3KeyForOutput(orderId, lineId, "tile"), "image/tiff", tileTiff);
      }
      if (output === "full_width" || output === "both") {
        fullUrl = await putPublicObject(s3KeyForOutput(orderId, lineId, "full_width"), "image/tiff", fullTiff);
      }

      const uploadId = getProp(li, "Scale Tool - Upload ID");
      if (uploadId) {
        const j = jobs.get(uploadId) || { upload_url: uploadUrl, created_at: Date.now(), outputs: {} };
        j.outputs = { ...j.outputs, tile: tileUrl, full_width: fullUrl, order_id: orderId, line_id: lineId };
        jobs.set(uploadId, j);
      }
    }

    res.status(200).send("ok");
  } catch (e) {
    console.error(e);
    res.status(500).send("error");
  }
});

app.get("/admin/uploads/:uploadId", basicAuth, (req, res) => {
  const j = jobs.get(req.params.uploadId);
  if (!j) return res.status(404).json({ error: "not_found" });
  res.json(j);
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(Number(PORT), () => console.log(`Server running on :${PORT}`));
