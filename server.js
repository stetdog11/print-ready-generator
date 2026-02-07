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
        .filter(({ props }) =>
  props.upload_url ||
  props.upload_id ||
  props["Scale Tool - Upload URL"] ||
  props["Scale Tool - Upload ID"]
);


      console.log(
        `Line items: ${lineItems.length} | Printable items: ${printableItems.length}`
      );

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

// ✅ Normalize property names from Shopify -> internal keys
if (!props.upload_id && props["Scale Tool - Upload ID"]) props.upload_id = props["Scale Tool - Upload ID"];
if (!props.upload_url && props["Scale Tool - Upload URL"]) props.upload_url = props["Scale Tool - Upload URL"];

if (!props.dpi && props["Scale Tool - DPI"]) props.dpi = props["Scale Tool - DPI"];
if (!props.tile_w && props["Scale Tool - Tile Width (in)"]) props.tile_w = props["Scale Tool - Tile Width (in)"];
if (!props.tile_h && props["Scale Tool - Tile Height (in)"]) props.tile_h = props["Scale Tool - Tile Height (in)"];
if (!props.rotate && props["Scale Tool - Rotation"]) props.rotate = props["Scale Tool - Rotation"];
if (!props.max_width_in && props["Scale Tool - Max Width (in)"]) props.max_width_in = props["Scale Tool - Max Width (in)"];
if (!props.qty && props["Scale Tool - Yards"]) props.qty = props["Scale Tool - Yards"];
if (!props.material && props["Scale Tool - Material"]) props.material = props["Scale Tool - Material"];

// (Optional) log after mapping so you can confirm it worked
console.log("✅ Normalized props:", {
  upload_id: props.upload_id,
  upload_url: props.upload_url,
  dpi: props.dpi,
  tile_w: props.tile_w,
  tile_h: props.tile_h,
  rotate: props.rotate,
  max_width_in: props.max_width_in,
  qty: props.qty,
  material: props.material,
});

// STEP C.2 — Download the uploaded image and log its size
const uploadUrl = props.upload_url;

        console.log("Downloading image:", uploadUrl);

        const imgRes = await fetch(uploadUrl);
        if (!imgRes.ok) {
          throw new Error(
            `Image download failed: ${imgRes.status} ${imgRes.statusText}`
          );
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
        const tileWIn = parseFloat(props.tile_w);
        const tileHIn = parseFloat(props.tile_h);
        const dpi = parseInt(props.dpi || "300", 10);

        const tileWpx = Math.round(tileWIn * dpi);
        const tileHpx = Math.round(tileHIn * dpi);

        console.log("Tile target (px):", tileWpx, tileHpx);

        const rotateDeg = Number(props.rotate || 0) || 0;

        // Rotate FIRST, then resize to exact target dims
        const tileBuf = await sharp(imgBuf)
          .rotate(rotateDeg)
          .flop() // mirror for sublimation
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
        for (let x = 0; x < tilesAcross; x++) {
          composites.push({
            input: tileBuf,
            left: x * tileWpx,
            top: 0,
          });
        }

        const rowBuf = await sharp({
          create: {
            width: fabricWidthPx,
            height: tileHpx,
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
  "Print File URL": tiffUrl,
  "Print Width": String(maxWidthIn || 64),
  "DPI": String(dpi || 300),
  "Repeat Size": repeatSize,
  "Rotation": String(rotateDeg || 0),
  "Yards": yards,
  // Optional if you have a definition for it:
  // "Material": String(props.material || ""),
});

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
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Preflight support
app.options("*", cors({ origin: true }));


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

const jobs = new Map(); // upload_id -> { upload_url, created_at, outputs: {tile, full_width, order_id, line_id} }

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

app.post("/webhooks/orders-create", express.raw({ type: "*/*" }), async (req, res) => {
  try {
    const hmac = req.headers["x-shopify-hmac-sha256"];
    const raw = req.body.toString("utf8");
    if (!verifyShopifyWebhook(raw, hmac)) return res.status(401).send("Invalid HMAC");

    const order = JSON.parse(raw);
    const orderId = order.id;

    for (const li of order.line_items || []) {
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
      const aspect = meta.height && meta.width ? meta.height / meta.width : 1;
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
          background: { r: 255, g: 255, b: 255, alpha: 1 },
        },
      })
        .composite(composites)
        .tiff({ compression: "lzw" })
        .toBuffer();

      const lineId = li.id || li.variant_id || "line";
      let tileUrl = null;
      let fullUrl = null;

      if (output === "tile" || output === "both") {
        tileUrl = await putPublicObject(
          s3KeyForOutput(orderId, lineId, "tile"),
          "image/tiff",
          tileTiff
        );
      }
      if (output === "full_width" || output === "both") {
        fullUrl = await putPublicObject(
          s3KeyForOutput(orderId, lineId, "full_width"),
          "image/tiff",
          fullTiff
        );
      }

      const uploadId =
        getProp(li, "Scale Tool - Upload ID") ||
        getProp(li, "upload_id");

      if (uploadId) {
        const j = jobs.get(uploadId) || {
          upload_url: uploadUrl,
          created_at: Date.now(),
          outputs: {},
        };

        j.outputs = {
          ...j.outputs,
          tile: tileUrl || j.outputs?.tile || null,
          full_width: fullUrl || j.outputs?.full_width || null,
          order_id: orderId || j.outputs?.order_id || null,
          line_id: lineId || j.outputs?.line_id || null,
          dashboard_url: process.env.APP_URL
            ? `${String(process.env.APP_URL).replace(/\/$/, "")}/admin/uploads/${encodeURIComponent(uploadId)}`
            : null,
        };

        jobs.set(uploadId, j);
      }
    }

    return res.status(200).send("ok");
  } catch (e) {
    console.error(e);
    return res.status(500).send("error");
  }
});


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

app.listen(LISTEN_PORT, "0.0.0.0", () => {
  console.log(`Server running on :${LISTEN_PORT}`);
});
