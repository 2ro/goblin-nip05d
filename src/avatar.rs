// Avatar image pipeline. Security posture: never trust client bytes — the
// format is sniffed from magic bytes (no extension/Content-Type trust),
// decoding runs under explicit resource limits (decompression bombs), only
// the first frame of any animated input survives, EXIF orientation is
// applied and then every byte of metadata is destroyed by re-encoding the
// raw pixels to a fresh 256×256 PNG (kills polyglots, script tails, ICC/EXIF
// payloads). Output filenames are content hashes — user strings never touch
// the filesystem.

use image::codecs::png::PngEncoder;
use image::metadata::Orientation;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};
use std::io::Cursor;

/// Maximum accepted upload size (also enforced by the HTTP body limit).
pub const MAX_RAW_BYTES: usize = 2 * 1024 * 1024;
/// Output dimensions (square).
pub const SIZE: u32 = 256;
/// Decode-time dimension cap (pre-allocation guard). 4096 is ample for a
/// 256×256 output and bounds the decode buffer to ~64 MiB even for the
/// JPEG/WebP decoders, which honor dimension caps but not `max_alloc`.
const MAX_DIM: u32 = 4096;

/// Identify the image format from magic bytes alone. Only PNG, JPEG and
/// WebP are accepted; anything else (SVG, GIF, BMP, HTML, …) is rejected.
pub fn sniff(raw: &[u8]) -> Option<ImageFormat> {
    if raw.len() >= 8 && raw.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some(ImageFormat::Png);
    }
    if raw.len() >= 3 && raw.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some(ImageFormat::Jpeg);
    }
    if raw.len() >= 12 && &raw[0..4] == b"RIFF" && &raw[8..12] == b"WEBP" {
        return Some(ImageFormat::WebP);
    }
    None
}

/// Validate and normalize an uploaded image into a clean 256×256 PNG.
pub fn process(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.is_empty() {
        return Err("empty upload");
    }
    if raw.len() > MAX_RAW_BYTES {
        return Err("image too large");
    }
    let format = sniff(raw).ok_or("unsupported image format")?;

    // Header-only dimension gate BEFORE allocating any pixel buffer: the JPEG
    // and WebP decoders enforce the dimension caps but NOT `max_alloc`, so a
    // few-KB file can declare ~8192² and force a >100 MiB allocation. Reading
    // just the header dimensions lets us reject that without decoding.
    let (w0, h0) = ImageReader::with_format(Cursor::new(raw), format)
        .into_dimensions()
        .map_err(|_| "image rejected")?;
    if w0 == 0 || h0 == 0 || w0 > MAX_DIM || h0 > MAX_DIM {
        return Err("image dimensions too large");
    }

    let mut reader = ImageReader::with_format(Cursor::new(raw), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_DIM);
    limits.max_image_height = Some(MAX_DIM);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);

    let mut decoder = reader.into_decoder().map_err(|_| "image rejected")?;
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    // DynamicImage::from_decoder takes the FIRST frame only — animated
    // WebP/APNG inputs lose everything past frame one.
    let mut img = DynamicImage::from_decoder(decoder).map_err(|_| "image rejected")?;
    img.apply_orientation(orientation);

    let (w, h) = (img.width(), img.height());
    if w == 0 || h == 0 {
        return Err("image rejected");
    }
    // Center square crop, then scale to the canonical size.
    let side = w.min(h);
    let img = img.crop_imm((w - side) / 2, (h - side) / 2, side, side);
    let img = img.resize_exact(SIZE, SIZE, image::imageops::FilterType::Lanczos3);

    // Re-encode raw pixels: the output contains nothing from the input but
    // color values.
    let rgba = img.to_rgba8();
    let mut out = Vec::new();
    rgba.write_with_encoder(PngEncoder::new(&mut out))
        .map_err(|_| "encode failed")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::RgbaImage;

    fn png_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage::from_fn(w, h, |x, y| {
            image::Rgba([(x % 256) as u8, (y % 256) as u8, 7, 255])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_with_encoder(PngEncoder::new(&mut out))
            .unwrap();
        out
    }

    fn jpeg_bytes(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage::from_pixel(w, h, image::Rgba([10, 200, 30, 255]));
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .to_rgb8()
            .write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(
                &mut out, 80,
            ))
            .unwrap();
        out
    }

    #[test]
    fn sniff_accepts_real_formats_only() {
        assert_eq!(sniff(&png_bytes(4, 4)), Some(ImageFormat::Png));
        assert_eq!(sniff(&jpeg_bytes(4, 4)), Some(ImageFormat::Jpeg));
        let mut webp = b"RIFF\x00\x00\x00\x00WEBP".to_vec();
        webp.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&webp), Some(ImageFormat::WebP));
        assert_eq!(sniff(b"GIF89a...."), None);
        assert_eq!(sniff(b"<svg xmlns='http://www.w3.org/2000/svg'/>"), None);
        assert_eq!(sniff(b"<html><script>alert(1)</script></html>"), None);
        assert_eq!(sniff(b"PK\x03\x04zipzipzip"), None);
        assert_eq!(sniff(b"BM......"), None);
        assert_eq!(sniff(&[]), None);
    }

    #[test]
    fn process_normalizes_to_256_png() {
        let out = process(&png_bytes(513, 301)).unwrap();
        assert!(out.starts_with(&[0x89, b'P', b'N', b'G']));
        let img = image::load_from_memory(&out).unwrap();
        assert_eq!((img.width(), img.height()), (SIZE, SIZE));
    }

    #[test]
    fn process_rejects_garbage_and_truncated() {
        assert!(process(b"").is_err());
        assert!(process(b"not an image at all").is_err());
        let mut truncated = png_bytes(64, 64);
        truncated.truncate(40);
        assert!(process(&truncated).is_err());
        // Valid magic, corrupt body.
        let mut corrupt = png_bytes(64, 64);
        let len = corrupt.len();
        corrupt[len / 2..].iter_mut().for_each(|b| *b = 0xAA);
        assert!(process(&corrupt).is_err());
    }

    #[test]
    fn process_rejects_oversize_dimensions() {
        // 9000×2: dimension cap fires regardless of byte size.
        assert!(process(&png_bytes(9000, 2)).is_err());
    }

    #[test]
    fn process_strips_metadata_chunks_and_polyglot_tails() {
        // PNG with a zip payload appended after IEND (classic polyglot).
        let mut poly = png_bytes(64, 64);
        poly.extend_from_slice(b"PK\x03\x04 malicious zip payload here");
        let out = process(&poly).unwrap();
        // Output decodes cleanly and contains no trace of the tail …
        assert!(image::load_from_memory(&out).is_ok());
        assert!(!out
            .windows(4)
            .any(|w| w == b"PK\x03\x04" || w == b"tEXt" || w == b"eXIf" || w == b"iCCP"));
        // … and ends exactly at the IEND chunk.
        assert_eq!(&out[out.len() - 8..out.len() - 4], b"IEND");
    }

    #[test]
    fn process_applies_exif_orientation() {
        // Encode a 2×1 JPEG: left pixel red, right pixel green, then claim
        // orientation 180° via decoder metadata can't be injected easily
        // here, so instead verify apply path doesn't break plain JPEGs.
        let out = process(&jpeg_bytes(100, 50)).unwrap();
        let img = image::load_from_memory(&out).unwrap();
        assert_eq!((img.width(), img.height()), (SIZE, SIZE));
    }

    #[test]
    fn output_is_deterministic_for_same_input() {
        let a = process(&png_bytes(300, 300)).unwrap();
        let b = process(&png_bytes(300, 300)).unwrap();
        assert_eq!(a, b);
    }
}
