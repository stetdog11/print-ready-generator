import express from "express";
import fs from "fs";
import path from "path";
import cors from "cors";
import morgan from "morgan";
import multer from "multer";
import crypto from "crypto";
import fetch from "node-fetch";
import sharp from "sharp";
import {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
  GetObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const s3 = new S3Client({
  region: process.env.S3_REGION,
  endpoint: process.env.S3_ENDPOINT,
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  },
});
// Separate client for DESIGN library (does NOT affect existing s3 client)
const designR2 = new S3Client({
  region: "auto",
  endpoint: process.env.DESIGN_ENDPOINT,
  credentials: {
    accessKeyId: process.env.DESIGN_ACCESS_KEY_ID,
    secretAccessKey: process.env.DESIGN_SECRET_ACCESS_KEY,
  },
});

const DESIGN_BUCKET = process.env.DESIGN_BUCKET;
const ORDERS_KEY = "orders/orders.json";
let orders = [];
const app = express();
app.use(morgan("dev"));

app.post(
  "/api/shopify/order-paid",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const body = req.body.toString("utf8");
      const order = JSON.parse(body);

      const orderId = order.id;

global.__processedOrders = global.__processedOrders || new Set();

// ---- Decide if we should process this order ----
// Normal payments:
const isPaid = String(order.financial_status || "").toLowerCase() === "paid";

// COD test / COD workflow:
const gateways = (order.payment_gateway_names || []).map(s => String(s).toLowerCase());
const isCOD =
  gateways.some(g => g.includes("cash on delivery") || g === "cod" || g.includes("cash_on_delivery"));

// If it's not paid AND not COD, do nothing (but DO NOT mark as processed)
if (!isPaid && !isCOD) {
  console.log("Skipping - not paid and not COD:", {
    orderId,
    financial_status: order.financial_status,
    payment_gateway_names: order.payment_gateway_names
  });
  return res.status(200).send("ok");
}

// ---- Now it's allowed to process, so dedupe safely ----
if (global.__processedOrders.has(orderId)) {
  console.log("Already processed order, skipping:", orderId);
  return res.status(200).send("ok");
}
console.log("Processing order:", {
  orderId,
  reason: isPaid ? "paid" : "cod",
  financial_status: order.financial_status,
  payment_gateway_names: order.payment_gateway_names
});
global.__processedOrders.add(orderId);


      console.log("ORDER WEBHOOK RECEIVED");
     const fullOrder = await fetchFullOrder(orderId);

const lineItems = fullOrder.line_items || [];

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
     .filter(({ props }) => {
  if (!props) return false;
  return Object.keys(props).some(k =>
    k.toLowerCase().includes("upload") &&
    props[k] &&
    String(props[k]).trim() !== ""
  );
});



      console.log(
  `Line items: ${lineItems.length} | Printable items: ${printableItems.length}`
);

let itemNumber = 1;

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

// --------------------
// ✅ Robust props normalize (supports ALL label variants)
// --------------------
function pick(props, ...names) {
  for (const n of names) {
    if (props[n] != null && String(props[n]).trim() !== "") return props[n];
  }
  return "";
}
function parseInches(v) {
  if (v == null) return null;
  const s = String(v).replace(/"/g, "").trim();
  const n = Number(s);
  return Number.isFinite(n) && n > 0 ? n : null;
}
function parseNumber(v) {
  if (v == null) return null;
  const s = String(v).replace(/"/g, "").trim();
  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

// upload_id / upload_url
props.upload_id = pick(
  props,
  "upload_id",
  "Scale Tool - Upload ID",
  "Scale Tool - Upload Id"
);
props.upload_url = pick(
  props,
  "upload_url",
  "Scale Tool - Upload URL",
  "Scale Tool - Upload Url"
);

// dpi (you lock at 300, but accept variants)
props.dpi = pick(
  props,
  "dpi",
  "Scale Tool - DPI",
  "Scale Tool - Dpi"
) || "300";

// tile width / height (accept all known names)
props.tile_w = pick(
  props,
  "tile_w",
  "tile_w_in",
  "Scale Tool - Tile Width (in)",
  "Scale Tool - Tile Width",
  "Scale Tool - Target Repeat Width (in)",
  "Scale Tool - Target Repeat Width",
  "Scale Tool - Target Repeat"
);

props.tile_h = pick(
  props,
  "tile_h",
  "tile_h_in",
  "Scale Tool - Tile Height (in)",
  "Scale Tool - Tile Height"
);

// rotation (accept deg variants)
props.rotate = pick(
  props,
  "rotate",
  "Scale Tool - Rotation",
  "Scale Tool - Rotation (deg)",
  "Scale Tool - Rotation (deg):"
) || "0";

// max width (accept variants, default 64)
props.max_width_in = pick(
  props,
  "max_width_in",
  "Scale Tool - Max Width (in)",
  "Scale Tool - Max Width",
  "Scale Tool - Max Width (in):"
) || "64";

// qty / yards
props.qty = pick(
  props,
  "qty",
  "Scale Tool - Yards",
  "Yards"
) || String(item.quantity || 1);

// material (optional, but keep it)
props.material = pick(
  props,
  "material",
  "Scale Tool - Material"
);

// Log after mapping so you can confirm it worked
console.log("✅ Normalized props:", {
  upload_id: props.upload_id,
  upload_url: props.upload_url,
  dpi: props.dpi,
  tile_w: props.tile_w,
  tile_h: props.tile_h,
  rotate: props.rotate,
  max_width_in: props.max_width_in,
  qty: props.qty,
  material: props.material
});

// --------------------
// ✅ HARD REQUIREMENT: we must have upload_url + tile_w
// --------------------
const uploadUrl = String(props.upload_url || "").trim();
if (!uploadUrl) {
  console.log("❌ Skipping item: missing upload_url");
  continue;
}

// Tile width is required to build repeat
const tileWIn = parseInches(props.tile_w);
if (!tileWIn) {
  console.log("❌ Skipping item: missing tile_w (repeat width)");
  continue;
}

// Tile height can be missing; we will auto-calc from image aspect later if needed
let tileHIn = parseInches(props.tile_h);

const dpi = Math.round(parseNumber(props.dpi) || 300);
const rotateDeg = parseNumber(props.rotate) || 0;
const maxWidthIn = parseNumber(props.max_width_in) || 64;
const yards = String(props.qty || item.quantity || 1);

// Expose these for later code (so you can keep your existing logic)
props.__tileWIn = tileWIn;
props.__tileHIn = tileHIn; // may be null
props.__dpi = dpi;
props.__rotateDeg = rotateDeg;
props.__maxWidthIn = maxWidthIn;
props.__yards = yards;


// STEP C.2 — Download the uploaded image and log its size
        
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
          height: meta.height,
        });

        // STEP C.4 — Build the scaled tile at 300 DPI

// ✅ If tile height is missing, derive it from image aspect ratio
if (!tileHIn) {
  const aspect = meta.height && meta.width ? meta.height / meta.width : 1;
  tileHIn = Math.max(1, Math.round(tileWIn * dpi * aspect)) / dpi;
  console.log("ℹ️ tile_h missing — derived from aspect:", { tileHIn });
}

// ✅ NOW compute px sizes (must exist before resize/log)
const tileWpx = Math.round(tileWIn * dpi);
const tileHpx = Math.round(tileHIn * dpi);

console.log("Tile target (px):", tileWpx, tileHpx);

        // Rotate FIRST, then resize to exact target dims
        const tileBuf = await sharp(imgBuf)
          .rotate(rotateDeg)
          .flop() // mirror for sublimation
          .resize(tileWpx, tileHpx, { fit: "cover" })
          .toBuffer();

        console.log("Tile buffer size (bytes):", tileBuf.length);
const tileMeta = await sharp(tileBuf).metadata();

console.log("Tile metadata:", {
  width: tileMeta.width,
  height: tileMeta.height,
});
        // STEP C.5 — Repeat tile across fabric width (one row)

// Build the TIFF exactly the size of one repeat
const fabricWidthPx = tileWpx;
const fabricHeightPx = tileHpx;

console.log("Fabric size (px):", fabricWidthPx, fabricHeightPx);

const tilesAcross = 1;
const tilesDown = 1;
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
            background: { r: 255, g: 255, b: 255, alpha: 0 },
          },
        })
          .composite(
            Array.from({ length: previewTilesAcross }).map((_, i) => ({
              input: tileBuf,
              left: i * tileWpx,
              top: 0,
            }))
          )
          .png()
          .toBuffer();

        console.log("Preview row buffer size (bytes):", previewRowBuf.length);

        // Build full-width strip (one row)
        const composites = [];

for (let y = 0; y < tilesDown; y++) {
  for (let x = 0; x < tilesAcross; x++) {
    composites.push({
      input: tileBuf,
      left: x * tileWpx,
      top: y * tileHpx,
    });
  }
}
if (
  tileWpx > fabricWidthPx ||
  tileHpx > fabricHeightPx
) {
  throw new Error(
    `Tile (${tileWpx}x${tileHpx}) is larger than canvas (${fabricWidthPx}x${fabricHeightPx})`
  );
}
        const rowBuf = await sharp({
  create: {
    width: fabricWidthPx,
    height: fabricHeightPx,
            channels: 4,
            background: { r: 255, g: 255, b: 255, alpha: 0 },
          },
        })
          .composite(composites)
          .png() // make buffer format explicit
          .toBuffer();

        console.log("Row buffer size (bytes):", rowBuf.length);

        // Convert DPI to pixels-per-mm for TIFF metadata
        const pxPerMm = dpi / 25.4;

        // Export full-width strip as TIFF
        const tiffBuf = await sharp(rowBuf)
          .tiff({
            compression: "lzw",
            xres: pxPerMm,
            yres: pxPerMm,
            resolutionUnit: "inch",
          })
          .toBuffer();

        console.log("FULL WIDTH TIFF size (bytes):", tiffBuf.length);

// Upload full-width TIFF
const lineId = item.id || item.variant_id || "line";
const tiffKey = s3KeyForOutput(orderId, lineId, "full_width");
const tiffUrl = await putPublicObject(tiffKey, "image/tiff", tiffBuf);

console.log("FULL WIDTH TIFF uploaded:", tiffUrl);
// ✅ Build dashboard URL (this is the link you click from Shopify)
const base = (process.env.APP_URL || "").replace(/\/$/, "");
const uploadId = props.upload_id ? String(props.upload_id) : "";
const dashboardUrl = uploadId ? `${base}/admin/uploads/${encodeURIComponent(uploadId)}` : "";

// ✅ Save output into jobs so the dashboard can show the button
if (uploadId) {
  const j = jobs.get(uploadId) || { upload_url: props.upload_url || "", created_at: Date.now(), outputs: {} };
  j.outputs = {
    ...j.outputs,
    full_width: tiffUrl,
    order_id: orderId,
    line_id: lineId,
  };
  jobs.set(uploadId, j);
}

// ---- WRITE RESULTS BACK TO SHOPIFY ORDER METAFIELDS ----
try {
  const shopDomain = process.env.SHOP || process.env.SHOP_DOMAIN;
  const adminToken = process.env.SHOPIFY_ADMIN_TOKEN;

  const repeatSize = `${tileWIn}" x ${tileHIn}"`;
  const yards = props.qty != null ? String(props.qty) : String(item.quantity || 1);

await setOrderMetafieldsByDisplayNames(shopDomain, adminToken, orderId, {
 [`Print File URL ${itemNumber}`]: tiffUrl,
  "Print Width": String(maxWidthIn || 64),
  "DPI": String(dpi || 300),
  "Repeat Size": repeatSize,
  "Rotation": String(rotateDeg || 0),
  "Yards": yards,
  // Optional if you have a definition for it:
  // "Material": String(props.material || ""),
});
itemNumber++;
} catch (e) {
  console.log("❌ Failed writing metafields back to Shopify:", e?.message || e);
}

        // stop before height stacking (safe)
        continue;
      }

      res.status(200).send("OK");
    } catch (err) {
      console.error("Webhook error:", err);
      res.status(500).send("Webhook error");
    }
  }
);

app.use(express.json({ type: ["application/json"] }));

// Allow Shopify Admin (and your shop domain) to call your API
app.use(cors({
  origin: true,
  methods: ["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Preflight support
app.options("*", cors({
  origin: true,
  methods: ["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
}));
async function loadOrders() {
  try {
    const command = new GetObjectCommand({
      Bucket: S3_BUCKET,
      Key: ORDERS_KEY,
    });

    const response = await s3.send(command);

    const text = await response.Body.transformToString();

    orders = JSON.parse(text);
  } catch {
    orders = [];
  }
}

async function saveOrders() {
  await putPublicObject(
    ORDERS_KEY,
    "application/json",
    Buffer.from(
      JSON.stringify(orders, null, 2)
    )
  );
}
app.post("/api/paybright/charge", async (req, res) => {
  try {
    const {
      amount,
      card,
      expiry_month,
      expiry_year,
      cvv2,
      name,
      customer,
    } = req.body || {};

    if (!amount || !card || !expiry_month || !expiry_year || !cvv2) {
      return res.status(400).json({ error: "Missing payment fields" });
    }

    const apiBase =
      process.env.PAYBRIGHT_API_BASE ||
      "https://api.sandbox.paybrightgateway.com/api/v2";

    const apiKey = process.env.PAYBRIGHT_API_KEY;
const pin = process.env.PAYBRIGHT_SECRET;

const auth = Buffer.from(`${apiKey}:${pin}`).toString("base64");

    const response = await fetch(`${apiBase}/transactions/charge`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${auth}`,
        "User-Agent": "ParadisePrintingCustomSite/1.0",
      },
      body: JSON.stringify({
        amount: Number(amount),
        card: String(card).replace(/\s/g, ""),
        expiry_month: Number(expiry_month),
        expiry_year: Number(expiry_year),
        cvv2: String(cvv2),
        name: name || customer?.name || "Paradise Printing Customer",
        capture: true,
        save_card: false,
        customer: {
          send_receipt: true,
          email: customer?.email || "",
        },
        billing_info: {
          first_name: customer?.name || "",
          phone: customer?.phone || "",
          zip: customer?.zip || "",
          country: "US",
        },
        transaction_details: {
          description: "Paradise Printing order",
          order_number: `PP-${Date.now()}`,
        },
      }),
    });

    const rawText = await response.text();
console.log("API KEY:", apiKey);
console.log("API Key EXISTS:", !!apiKey);
console.log("PAYBRIGHT STATUS:", response.status);
console.log("PAYBRIGHT RESPONSE:", rawText);

let data = {};
try {
  data = rawText ? JSON.parse(rawText) : {};
} catch {
  data = { raw: rawText };
}

if (!response.ok) {
  return res.status(response.status).json({
    error: "PayBright charge failed",
    status: response.status,
    details: data,
  });
}

const orderRecord = {
  id: data.reference_number,
  date: new Date().toISOString(),
  amount,
  status: data.status,
  customer,
  cartItems: req.body.cartItems || [],
  tiffUrls: [],
};

orders.unshift(orderRecord);

for (const [itemIndex, item] of (req.body.cartItems || []).entries()) {
  try {
    if (item.productType === "shirt") {
  console.log(
    `Skipping TIFF generation for shirt item ${itemIndex + 1}`
  );
  continue;
}
    const imageUrl = item.uploadUrl || item.image;

    if (!imageUrl) continue;

    const repeatSize = Number(item.repeatSize || 1);
const dpi = 300;
const rotateDeg = Number(item.rotation || 0);
console.log("Downloading image:", imageUrl);
    const imgRes = await fetch(imageUrl);

    if (!imgRes.ok) {
      throw new Error(`Image download failed: ${imgRes.status}`);
    }

    const imgBuf = Buffer.from(
      await imgRes.arrayBuffer()
    );

    const meta = await sharp(imgBuf, { failOn: "none" }).metadata();

    const aspect =
      meta.height && meta.width
        ? meta.height / meta.width
        : 1;

    const tileWpx = Math.round(repeatSize * dpi);
    const tileHpx = Math.round(tileWpx * aspect);

    const tileBuf = await sharp(imgBuf)
      .rotate(rotateDeg)
      .flop()
      .resize(tileWpx, tileHpx, { fit: "cover" })
      .toBuffer();
const tileMeta = await sharp(tileBuf).metadata();

console.log("Tile metadata:", {
  width: tileMeta.width,
  height: tileMeta.height,
});
    // Generate exactly ONE repeat tile
const fabricWidthPx = tileWpx;
const fabricHeightPx = tileHpx;

const tilesAcross = 1;
const tilesDown = 1;

    const composites = [];

for (let y = 0; y < tilesDown; y++) {
  for (let x = 0; x < tilesAcross; x++) {
    composites.push({
      input: tileBuf,
      left: x * tileWpx,
      top: y * tileHpx,
    });
  }
}
if (
  tileWpx > fabricWidthPx ||
  tileHpx > fabricHeightPx
) {
  throw new Error(
    `Tile (${tileWpx}x${tileHpx}) is larger than canvas (${fabricWidthPx}x${fabricHeightPx})`
  );
}
    const rowBuf = await sharp({
      create: {
        width: fabricWidthPx,
        height: fabricHeightPx,
        channels: 4,
        background: {
          r: 255,
          g: 255,
          b: 255,
          alpha: 0,
        },
      },
    })
      .composite(composites)
      .png()
      .toBuffer();

    const pxPerMm = dpi / 25.4;

    const tiffBuf = await sharp(rowBuf)
      .tiff({
        compression: "lzw",
        xres: pxPerMm,
        yres: pxPerMm,
        resolutionUnit: "inch",
      })
      .toBuffer();

    const safeUploadId = item.uploadId || "library";

const tiffKey =
  `outputs/orders/${data.reference_number}-${safeUploadId}-item-${itemIndex + 1}.tiff`;

    const tiffUrl = await putPublicObject(
      tiffKey,
      "image/tiff",
      tiffBuf
    );

    orderRecord.tiffUrls.push(tiffUrl);

        console.log("TIFF CREATED:", tiffUrl);
    console.log("Repeat size:", repeatSize);
    console.log("Tiles across:", tilesAcross);
  } catch (err) {
    console.error(
      `TIFF GENERATION FAILED FOR ITEM ${itemIndex + 1}`,
      err
    );
  }
}
    await saveOrders();
    
console.log("ORDER SAVED:", data.reference_number);
return res.json(data);
  } catch (err) {
    console.error("PayBright charge error:", err);
    return res.status(500).json({ error: err.message || "Payment error" });
  }
});
// ---- T-SHIRT DESIGN LIBRARY ----
const SHIRT_DESIGN_PREFIX = "shirt-designs/";

const shirtUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 },
});
const SHIRT_CATALOG_KEY = "shirt-designs/catalog.json";

async function getShirtCatalog() {
  try {
    const result = await designR2.send(
      new GetObjectCommand({
        Bucket: DESIGN_BUCKET,
        Key: SHIRT_CATALOG_KEY,
      })
    );

    const body = await result.Body.transformToString();
    return JSON.parse(body);
  } catch (err) {
    if (
      err.name === "NoSuchKey" ||
      err.$metadata?.httpStatusCode === 404
    ) {
      return [];
    }

    throw err;
  }
}

async function saveShirtCatalog(catalog) {
  await designR2.send(
    new PutObjectCommand({
      Bucket: DESIGN_BUCKET,
      Key: SHIRT_CATALOG_KEY,
      Body: JSON.stringify(catalog, null, 2),
      ContentType: "application/json",
    })
  );
}
// List all shirt designs
app.get("/api/shirt-designs", async (req, res) => {
  try {
    const catalog = await getShirtCatalog();

    const items = await Promise.all(
      catalog.map(async (item) => {
        try {
          const url = await getSignedUrl(
            designR2,
            new GetObjectCommand({
              Bucket: DESIGN_BUCKET,
              Key: item.key,
            }),
            {
              expiresIn: 60 * 60,
            }
          );

          const imageUrls =
  await Promise.all(
    (Array.isArray(item.images)
      ? item.images
      : []
    ).map(async (imageKey) => {
      try {
        return await getSignedUrl(
          designR2,
          new GetObjectCommand({
            Bucket: DESIGN_BUCKET,
            Key: imageKey,
          }),
          {
            expiresIn: 60 * 60,
          }
        );
      } catch (err) {
        console.error(
          "shirt gallery URL error:",
          imageKey,
          err
        );

        return null;
      }
    })
  );

return {
  ...item,
  url,
  imageUrls:
    imageUrls.filter(Boolean),
};
        } catch (err) {
          console.error(
            "shirt design URL error:",
            item.key,
            err
          );

          return null;
        }
      })
    );

    res.json({
      items: items.filter(Boolean),
    });
  } catch (err) {
    console.error(
      "shirt-designs list error:",
      err
    );

    res.status(500).json({
      error: "Failed to load shirt designs",
    });
  }
});
// Upload new shirt design
app.post(
  "/api/shirt-designs",
  shirtUpload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "No file uploaded",
        });
      }

      const designName = String(
        req.body.name || req.file.originalname
      ).trim();

      const price = Number(req.body.price || 0);

      const available =
        String(req.body.available || "true") === "true";

      const safeName = req.file.originalname.replace(
        /[^\w.\-() ]+/g,
        "_"
      );

      const key =
        `${SHIRT_DESIGN_PREFIX}${Date.now()}-${safeName}`;

      await designR2.send(
        new PutObjectCommand({
          Bucket: DESIGN_BUCKET,
          Key: key,
          Body: req.file.buffer,
          ContentType:
            req.file.mimetype ||
            "application/octet-stream",
        })
      );

      const catalog = await getShirtCatalog();

      const sizes = Array.isArray(req.body.sizes)
  ? req.body.sizes
  : String(req.body.sizes || "")
      .split(",")
      .map((size) => size.trim())
      .filter(Boolean);

const colors = Array.isArray(req.body.colors)
  ? req.body.colors
  : String(req.body.colors || "")
      .split(",")
      .map((color) => color.trim())
      .filter(Boolean);

const images = Array.isArray(req.body.images)
  ? req.body.images
  : [];

const catalogItem = {
  key,
  name: designName,
  price,
  available,
  sizes,
  colors,
  images,
  createdAt: new Date().toISOString(),
};

      catalog.unshift(catalogItem);

      await saveShirtCatalog(catalog);

      const url = await getSignedUrl(
        designR2,
        new GetObjectCommand({
          Bucket: DESIGN_BUCKET,
          Key: key,
        }),
        {
          expiresIn: 60 * 60,
        }
      );

      res.json({
        success: true,
        ...catalogItem,
        url,
      });
    } catch (err) {
      console.error(
        "shirt-design upload error:",
        err
      );

      res.status(500).json({
        error: "Failed to upload shirt design",
      });
    }
  }
);
// Upload additional image for an existing shirt design
app.post(
  "/api/shirt-designs/image",
  shirtUpload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "No image uploaded",
        });
      }

      const shirtKey = String(
        req.body.key || ""
      ).trim();

      if (
        !shirtKey ||
        !shirtKey.startsWith(
          SHIRT_DESIGN_PREFIX
        )
      ) {
        return res.status(400).json({
          error: "Invalid shirt design key",
        });
      }

      const catalog =
        await getShirtCatalog();

      const index = catalog.findIndex(
        (item) => item.key === shirtKey
      );

      if (index === -1) {
        return res.status(404).json({
          error: "Shirt design not found",
        });
      }

      const safeName =
        req.file.originalname.replace(
          /[^\w.\-() ]+/g,
          "_"
        );

      const imageKey =
        `${SHIRT_DESIGN_PREFIX}gallery/` +
        `${Date.now()}-${safeName}`;

      await designR2.send(
        new PutObjectCommand({
          Bucket: DESIGN_BUCKET,
          Key: imageKey,
          Body: req.file.buffer,
          ContentType:
            req.file.mimetype ||
            "application/octet-stream",
        })
      );

      const images = Array.isArray(
        catalog[index].images
      )
        ? catalog[index].images
        : [];

      catalog[index] = {
        ...catalog[index],
        images: [
          ...images,
          imageKey,
        ],
      };

      await saveShirtCatalog(catalog);

      const url = await getSignedUrl(
        designR2,
        new GetObjectCommand({
          Bucket: DESIGN_BUCKET,
          Key: imageKey,
        }),
        {
          expiresIn: 60 * 60,
        }
      );

      res.json({
        success: true,
        key: imageKey,
        url,
        images: catalog[index].images,
      });
    } catch (err) {
      console.error(
        "shirt gallery upload error:",
        err
      );

      res.status(500).json({
        error:
          "Failed to upload shirt image",
      });
    }
  }
);
// Delete shirt design
app.delete("/api/shirt-designs", async (req, res) => {
  try {
    const key = String(req.query.key || "");

    if (!key.startsWith(SHIRT_DESIGN_PREFIX)) {
      return res.status(400).json({
        error: "Invalid shirt design key",
      });
    }

    await designR2.send(
      new DeleteObjectCommand({
        Bucket: DESIGN_BUCKET,
        Key: key,
      })
    );

    const catalog = await getShirtCatalog();

    const updatedCatalog = catalog.filter(
      (item) => item.key !== key
    );

    await saveShirtCatalog(updatedCatalog);

    res.json({
      success: true,
    });
  } catch (err) {
    console.error(
      "shirt-design delete error:",
      err
    );

    res.status(500).json({
      error: "Failed to delete shirt design",
    });
  }
});
// Update shirt design metadata
app.patch("/api/shirt-designs", async (req, res) => {
  try {
  const {
  key,
  name,
  price,
  available,
  sizes,
  colors,
  images,
} = req.body || {};

    if (
      !key ||
      !String(key).startsWith(SHIRT_DESIGN_PREFIX)
    ) {
      return res.status(400).json({
        error: "Invalid shirt design key",
      });
    }

    const catalog = await getShirtCatalog();

    const index = catalog.findIndex(
      (item) => item.key === key
    );

    if (index === -1) {
      return res.status(404).json({
        error: "Shirt design not found",
      });
    }

    catalog[index] = {
      ...catalog[index],
      name:
        name !== undefined
          ? String(name).trim()
          : catalog[index].name,
      price:
        price !== undefined
          ? Number(price)
          : catalog[index].price,
      available:
        available !== undefined
          ? Boolean(available)
          : catalog[index].available,
      sizes:
  sizes !== undefined && Array.isArray(sizes)
    ? sizes
    : catalog[index].sizes || [],

colors:
  colors !== undefined && Array.isArray(colors)
    ? colors
    : catalog[index].colors || [],

images:
  images !== undefined && Array.isArray(images)
    ? images
    : catalog[index].images || [],
    };

    await saveShirtCatalog(catalog);

    res.json({
      success: true,
      item: catalog[index],
    });
  } catch (err) {
    console.error(
      "shirt-design update error:",
      err
    );

    res.status(500).json({
      error: "Failed to update shirt design",
    });
  }
});
// ---- DESIGN LIBRARY API (folders + designs) ----
app.get("/api/design-health", (req, res) => {
  res.json({ ok: true, bucket: process.env.DESIGN_BUCKET || null });
});

// List top-level "folders"
app.get("/api/design-folders", async (req, res) => {
  try {
    const out = await designR2.send(
      new ListObjectsV2Command({
        Bucket: DESIGN_BUCKET,
        Delimiter: "/",
      })
    );

    const folders = (out.CommonPrefixes || [])
      .map((p) => p.Prefix.replace(/\/$/, ""))
      .filter(Boolean);

    res.json({ folders });
  } catch (err) {
    console.error("design-folders error", err);
    res.status(500).json({ error: "Failed to list folders" });
  }
});

// List designs inside a folder (signed URLs)
app.get("/api/designs", async (req, res) => {
  try {
    const folder = String(req.query.folder || "").trim();
    if (!folder) return res.status(400).json({ error: "Folder required" });

    const prefix = folder.replace(/\/+$/, "") + "/";

    const out = await designR2.send(
      new ListObjectsV2Command({
        Bucket: DESIGN_BUCKET,
        Prefix: prefix,
      })
    );

    const keys = (out.Contents || [])
      .map((o) => o.Key)
      .filter((k) => k && !k.endsWith("/"));

    const items = await Promise.all(
      keys.map(async (Key) => {
        const url = await getSignedUrl(
          designR2,
          new GetObjectCommand({ Bucket: DESIGN_BUCKET, Key }),
          { expiresIn: 60 * 60 } // 1 hour
        );
        return { key: Key, url };
      })
    );

    res.json({ folder, items });
  } catch (err) {
    console.error("designs error", err);
    res.status(500).json({ error: "Failed to list designs" });
  }
});


app.get("/api/health", (req, res) => {
  res.status(200).json({ ok: true, ts: Date.now() });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 40 * 1024 * 1024 },
}); // 40MB

const {
  PORT,
  SHOPIFY_WEBHOOK_SECRET,

  S3_REGION,
  S3_ENDPOINT,
  S3_BUCKET,
  S3_ACCESS_KEY_ID,
  S3_SECRET_ACCESS_KEY,
  S3_PUBLIC_BASE,
SHOPIFY_API_KEY,
SHOPIFY_API_SECRET,
SHOP,
APP_URL,

  OUTPUT_DPI = "300",
  FABRIC_WIDTH_IN = "54",

  ADMIN_USER,
  ADMIN_PASS,
} = process.env;

const jobs = new Map();

function basicAuth(req, res, next) {
  if (!ADMIN_USER || !ADMIN_PASS) return next();
  const hdr = req.headers.authorization || "";
  const [type, token] = hdr.split(" ");
  if (type !== "Basic" || !token)
    return res.status(401).set("WWW-Authenticate", "Basic").send("Auth required");
  const [u, p] = Buffer.from(token, "base64").toString("utf8").split(":");
  if (u !== ADMIN_USER || p !== ADMIN_PASS)
    return res.status(403).send("Forbidden");
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
    ContentType: contentType,
  });
  await s3.send(cmd);
  return `${S3_PUBLIC_BASE.replace(/\/$/, "")}/${key}`;
}

function verifyShopifyWebhook(rawBody, hmacHeader) {
  if (!SHOPIFY_WEBHOOK_SECRET) return false;
  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(rawBody, "utf8")
    .digest("base64");
  try {
    return crypto.timingSafeEqual(
      Buffer.from(digest),
      Buffer.from(hmacHeader || "")
    );
  } catch {
    return false;
  }
}

// ---------------- SHOPIFY HELPERS (ORDER METAFIELDS) ----------------

const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2025-01";


/* ===============================
   FULL ORDER FETCH (REQUIRED)
   =============================== */
async function fetchFullOrder(orderId) {
  const shopDomain = process.env.SHOP || process.env.SHOP_DOMAIN;
  const adminToken = process.env.SHOPIFY_ADMIN_TOKEN;

  if (!shopDomain) throw new Error("Missing SHOP env");
  if (!adminToken) throw new Error("Missing SHOPIFY_ADMIN_TOKEN env");

 const url = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/orders/${orderId}.json`;

  const resp = await fetch(url, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": adminToken,
    },
  });

  const json = await resp.json();

  if (!resp.ok) {
    throw new Error(`Failed to fetch full order ${orderId}: ${resp.status}`);
  }

  return json.order;
}

async function shopifyGraphQL(shopDomain, adminToken, query, variables = {}) {
  if (!shopDomain) throw new Error("Missing SHOP env (e.g. paradise-printing-2.myshopify.com)");
  if (!adminToken) throw new Error("Missing SHOPIFY_ADMIN_TOKEN env");

  const url = `https://${shopDomain}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": adminToken,
    },
    body: JSON.stringify({ query, variables }),
  });

  const json = await resp.json();

  if (!resp.ok) {
    throw new Error(`Shopify GraphQL HTTP ${resp.status}: ${JSON.stringify(json).slice(0, 800)}`);
  }
  if (json.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors).slice(0, 800)}`);
  }

  return json.data;
}


async function getOrderMetafieldDefinitionsByName(shopDomain, adminToken) {
  // Pull metafield definitions for ORDER and map by display name -> {namespace, key, type}
  const q = `
    query defs($first:Int!) {
      metafieldDefinitions(first:$first, ownerType: ORDER) {
        nodes {
          name
          namespace
          key
          type { name }
        }
      }
    }
  `;
  const data = await shopifyGraphQL(shopDomain, adminToken, q, { first: 100 });
  const nodes = data?.metafieldDefinitions?.nodes || [];
  const map = new Map();
  for (const d of nodes) {
    if (!d?.name) continue;
    map.set(String(d.name).trim().toLowerCase(), {
      namespace: d.namespace,
      key: d.key,
      type: d.type?.name || "single_line_text_field",
    });
   
  }
  return map;
}

function coerceMetafieldValue(typeName, value) {
  // Keep it safe and predictable
  const t = String(typeName || "").toLowerCase();
  if (value == null) return "";

  // Shopify expects "number_integer" and "number_decimal" as strings too.
  if (t.includes("number_integer")) return String(parseInt(value, 10) || 0);
  if (t.includes("number_decimal")) return String(Number(value) || 0);

  // For URL type, string is fine.
  return String(value);
}

async function setOrderMetafieldsByDisplayNames(shopDomain, adminToken, orderIdNum, fieldsByDisplayName) {
  // fieldsByDisplayName example:
  // { "Print File URL": "https://...", "DPI": "300", "Print Width": "64", ... }
  const defMap = await getOrderMetafieldDefinitionsByName(shopDomain, adminToken);

  const ownerId = `gid://shopify/Order/${orderIdNum}`;
  const metafields = [];

  for (const [displayName, rawVal] of Object.entries(fieldsByDisplayName || {})) {
    const def = defMap.get(String(displayName).trim().toLowerCase());
    if (!def) {
      console.log(`⚠️ Metafield definition not found for display name: "${displayName}". Skipping.`);
      continue;
    }

    metafields.push({
      ownerId,
      namespace: def.namespace,
      key: def.key,
      type: def.type, // must match the definition type
      value: coerceMetafieldValue(def.type, rawVal),
    });
  }

  if (!metafields.length) {
    console.log("⚠️ No metafields to write (none matched definitions).");
    return;
  }

  const m = `
    mutation set($metafields:[MetafieldsSetInput!]!) {
      metafieldsSet(metafields:$metafields) {
        metafields { id namespace key }
        userErrors { field message }
      }
    }
  `;

  const data = await shopifyGraphQL(shopDomain, adminToken, m, { metafields });

  const errs = data?.metafieldsSet?.userErrors || [];
  if (errs.length) {
    console.log("❌ metafieldsSet userErrors:", errs);
  } else {
    console.log("✅ Order metafields updated:", data?.metafieldsSet?.metafields?.length || 0);
  }
} // <-- end of setOrderMetafieldsByDisplayNames
app.post("/api/print-ready", async (req, res) => {
  try {
    const orderGid = String(req.query.orderGid || "").trim();
    if (!orderGid) return res.status(400).json({ error: "missing_orderGid" });

    const orderId = orderGid.split("/").pop();
    if (!orderId) return res.status(400).json({ error: "bad_orderGid" });

    const shopDomain = process.env.SHOP || process.env.SHOP_DOMAIN;
    const adminToken = process.env.SHOPIFY_ADMIN_TOKEN;

    const q = `
      query($id: ID!) {
        order(id: $id) {
          metafields(first: 50) {
            nodes { namespace key value }
          }
        }
      }
    `;

    const data = await shopifyGraphQL(shopDomain, adminToken, q, {
      id: `gid://shopify/Order/${orderId}`,
    });

    const nodes = data?.order?.metafields?.nodes || [];

    const hit = nodes.find(m =>
      m.namespace === "custom" &&
      (m.key === "print_file_url" || m.key === "print-file-url")
    );

    if (!hit || !hit.value) {
      return res.status(404).json({
        error: "print_file_url_missing",
        availableMetafields: nodes.map(m => `${m.namespace}.${m.key}`),
      });
    }

    const downloadUrl = hit.value;

    return res.json({
      downloadUrl,
      previewUrl: downloadUrl,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e?.message || "error" });
  }
});

app.post("/api/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "missing_file" });
    const uploadId = crypto.randomBytes(12).toString("hex");
    const key = s3KeyForUpload(uploadId, req.file.originalname);
    const uploadUrl = await putPublicObject(
      key,
      req.file.mimetype || "application/octet-stream",
      req.file.buffer
    );
    jobs.set(uploadId, { upload_url: uploadUrl, created_at: Date.now(), outputs: {} });
    res.json({ upload_id: uploadId, upload_url: uploadUrl });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "upload_failed" });
  }
});

function getProp(lineItem, name) {
  const props = lineItem.properties || [];
  const hit = props.find((p) => (p.name || p.key) === name);
  return hit ? hit.value ?? "" : "";
}
function parseInches(str) {
  if (!str) return null;
  const v = String(str).replace(/"/g, "").trim();
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

app.get("/admin/uploads/:uploadId", basicAuth, (req, res) => {
  const uploadId = req.params.uploadId;
  const j = jobs.get(uploadId);

  if (!j) {
    return res.status(404).send(`
      <html><body style="font-family:Arial;padding:20px">
        <h2>Not found</h2>
        <p>No job found for upload_id: <b>${escapeHtml(uploadId)}</b></p>
      </body></html>
    `);
  }

  const fileUrl = j?.outputs?.full_width || "";
  const orderId = j?.outputs?.order_id || "";
  const lineId = j?.outputs?.line_id || "";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Print Dashboard</title>
</head>
<body style="font-family:Arial, sans-serif;background:#f6f7f8;margin:0;padding:24px">
  <div style="max-width:760px;margin:0 auto;background:#fff;border-radius:14px;padding:18px;box-shadow:0 6px 24px rgba(0,0,0,.08)">
    <h2 style="margin:0 0 10px 0">Print Dashboard</h2>

    <div style="font-size:14px;line-height:1.5;color:#333;background:#f2f4f6;border-radius:12px;padding:12px">
      <div><b>Upload ID:</b> ${escapeHtml(uploadId)}</div>
      ${orderId ? `<div><b>Order ID:</b> ${escapeHtml(String(orderId))}</div>` : ``}
      ${lineId ? `<div><b>Line ID:</b> ${escapeHtml(String(lineId))}</div>` : ``}
    </div>

    <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
      ${
        fileUrl
          ? `<a href="${fileUrl}" target="_blank" rel="noopener noreferrer"
               style="display:inline-block;background:#14b8a6;color:#fff;text-decoration:none;
                      padding:12px 14px;border-radius:12px;font-weight:700">
               Open Print File
             </a>`
          : `<div style="color:#b00020;font-weight:700">No print file yet (full_width missing)</div>`
      }

      ${
        fileUrl
          ? `<button onclick="copyText()"
              style="border:0;background:#14b8a6;color:#fff;padding:12px 14px;border-radius:12px;font-weight:700;cursor:pointer">
              Copy File URL
            </button>`
          : ``
      }
    </div>

    <div style="margin-top:14px;font-size:13px;color:#666">
      Tip: If the file isn’t ready yet, refresh this page after a minute.
    </div>
  </div>

<script>
  const FILE_URL = ${JSON.stringify(fileUrl || "")};
  function copyText(){
    if (!FILE_URL) return;
    navigator.clipboard.writeText(FILE_URL)
      .then(()=>alert("Copied!"))
      .catch(()=>prompt("Copy this:", FILE_URL));
  }
</script>
</body>
</html>
  `);
});

// helper for HTML safety (keep OUTSIDE routes)
function escapeHtml(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


app.get("/health", (req, res) => res.json({ ok: true }));
app.get("/", (req, res) => {
  res.status(200).send("Print Ready Generator App is running");
});
function buildInstallUrl({ shop, scopes, redirectUri, state }) {
  const params = new URLSearchParams({
    client_id: process.env.SHOPIFY_API_KEY,
    scope: scopes,
    redirect_uri: redirectUri,
    state,
  });
  return `https://${shop}/admin/oauth/authorize?${params.toString()}`;
}

// 1) Start OAuth (you can hit this in your browser)
app.get("/auth", (req, res) => {
  const shop = (req.query.shop || process.env.SHOP || "").toString().trim();
  if (!shop) return res.status(400).send("Missing ?shop=your-store.myshopify.com");

  const scopes = (process.env.SCOPES || "read_orders,write_orders,read_products,write_products").trim();
  const redirectUri = `${process.env.APP_URL.replace(/\/$/, "")}/auth/callback`;

  const state = crypto.randomBytes(16).toString("hex");
  // store state in memory temporarily (good enough for your single-store setup)
  global.__oauthState = state;

  const installUrl = buildInstallUrl({ shop, scopes, redirectUri, state });
  return res.redirect(installUrl);
});

function verifyOAuthHmac(query, secret) {
  const q = { ...query };
  const providedHmac = String(q.hmac || "");
  delete q.hmac;
  delete q.signature; // old param, just in case

  const message = Object.keys(q)
    .sort()
    .map((k) => `${k}=${Array.isArray(q[k]) ? q[k].join(",") : q[k]}`)
    .join("&");

  const digest = crypto.createHmac("sha256", secret).update(message).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(providedHmac, "utf8"));
}

app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code, state } = req.query;

    if (!shop || !code) return res.status(400).send("Missing shop or code");
    if (!state || state !== global.__oauthState) return res.status(400).send("Invalid state");

    // ✅ Verify HMAC from Shopify
    if (!verifyOAuthHmac(req.query, process.env.SHOPIFY_API_SECRET)) {
      return res.status(400).send("Invalid HMAC");
    }

    const tokenUrl = `https://${shop}/admin/oauth/access_token`;

    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: process.env.SHOPIFY_API_KEY,
        client_secret: process.env.SHOPIFY_API_SECRET,
        code,
      }),
    });

    const data = await tokenRes.json();

    if (!data.access_token) {
      console.error("❌ Token exchange failed:", data);
      return res.status(500).send("Token exchange failed. Check Render logs.");
    }

    return res.send("✅ Installed. Check Render logs for SHOPIFY_ADMIN_TOKEN.");
  } catch (err) {
    console.error("❌ /auth/callback error:", err);
    return res.status(500).send("Callback error. Check Render logs.");
  }
});
const LISTEN_PORT = Number(process.env.PORT || 8080);
app.get("/api/orders", (req, res) => {
  res.json(orders);
});
app.post("/api/orders/:id/complete", async (req, res) => {
  const order = orders.find(
    (o) => String(o.id) === String(req.params.id)
  );

  if (!order) {
    return res.status(404).json({
      error: "Order not found",
    });
  }

  order.status = "Completed";

  await saveOrders();

  res.json({
    success: true,
  });
});

app.delete("/api/orders/:id", async (req, res) => {
  orders = orders.filter(
    (o) => String(o.id) !== String(req.params.id)
  );

  await saveOrders();

  res.json({
    success: true,
  });
});
await loadOrders();
app.listen(LISTEN_PORT, "0.0.0.0", () => {
  console.log(`Server running on :${LISTEN_PORT}`);
});
