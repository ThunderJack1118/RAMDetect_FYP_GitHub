"""
ramdetect/reporting/pdf_reporter.py
─────────────────────────────────────
Generates a forensic PDF report from a ScanSession using ReportLab.

Design: Corporate White
  • White page body, dark navy header + footer on every page
  • Dedicated cover page with large verdict badge
  • Colour-coded section dividers and status indicators
  • Clean sans-serif typography throughout

Falls back to a plain-text file when ReportLab is not installed.
"""

from __future__ import annotations
import os
from datetime import datetime
from typing import Any, Dict
from .visualizer import ChartBuilder
from .report_only_artifacts import collect_report_only_ransomware_artifacts

try:
    from ramdetect.utils.process_confidence import confidence_label as _j10_conf_label, confidence_tooltip as _j10_conf_tooltip
except Exception:
    def _j10_conf_label(proc):
        return str(proc.get("process_confidence_label") or proc.get("process_confidence") or "Not assessed") if isinstance(proc, dict) else "Not assessed"
    def _j10_conf_tooltip(proc):
        return "Process confidence was not assessed for this session."

_HAS_REPORTLAB = False
try:
    import reportlab
    _HAS_REPORTLAB = True
except ImportError:
    pass


def _bytes_str(path: str) -> str:
    try:
        n = os.path.getsize(path)
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} GB"
    except Exception:
        return "—"

def _pick(d: dict, *keys, default: str = "?") -> str:
    for k in keys:
        v = d.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return str(default)

def _missing_artifact_value(value) -> bool:
    if value is None:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value) == 0
    text = str(value).strip()
    return text == "" or text.lower() in {"none", "n/a", "na", "?", "-", "0", "0x0"}

def _first_artifact_value(d: dict, *keys):
    for key in keys:
        value = d.get(key) if isinstance(d, dict) else None
        if not _missing_artifact_value(value):
            return value
    return None

def _fmt_hex_artifact(value, default: str = "N/A") -> str:
    if _missing_artifact_value(value):
        return default
    try:
        if isinstance(value, str):
            text = value.strip()
            n = int(text, 16) if text.lower().startswith("0x") else int(float(text))
        else:
            n = int(value)
        return f"0x{n:X}"
    except Exception:
        return str(value).strip() or default

def _artifact_is_injection_like(pe: dict) -> bool:
    if not isinstance(pe, dict):
        return False
    if pe.get("i2f_feature_flag") or pe.get("source") == "ramdetect_i2f_kernel_start_plus_suspicious_path":
        return True
    text = " ".join(str(pe.get(k, "")) for k in (
        "type", "name", "section", "section_name", "anomaly", "anomalies",
        "source", "policy", "details", "status_reason", "reason",
    )).lower()
    terms = (
        "injection candidate", "code injection", "malfind", "suspicious thread location",
        "kernel start", "suspicious path injection", "thread start in private",
        "private executable", "private rwx", "unbacked", "shellcode", "hollow",
        "mz/pe in private", "pe in anonymous",
    )
    return any(term in text for term in terms)

def _artifact_addr(pe: dict) -> str:
    return _fmt_hex_artifact(_first_artifact_value(
        pe, "address", "virtual_address", "start_address", "thread_start_address",
        "vad_start", "start", "va", "virt_addr", "VirtualAddress", "base_address"
    ))

def _artifact_size(pe: dict) -> str:
    return _fmt_hex_artifact(_first_artifact_value(
        pe, "region_size", "vad_size", "size", "virt_size", "VirtualSize"
    ))

def _artifact_protection(pe: dict) -> str:
    value = _first_artifact_value(
        pe, "protection", "vad_protection", "matched_vad_protection",
        "page_protection", "memory_protection", "permissions", "permission",
        "perms", "Characteristics"
    )
    if value is None:
        return "UNKNOWN" if (pe.get("is_suspicious") or _artifact_is_injection_like(pe)) else "N/A"
    return str(value).strip()

def _artifact_evidence_note(pe: dict) -> str:
    pieces = []
    for key in ("address_source", "size_source", "protection_source"):
        value = pe.get(key)
        if not _missing_artifact_value(value):
            pieces.append(f"{key.replace('_', ' ')}: {value}")
    if not pieces and _artifact_protection(pe).upper() == "UNKNOWN":
        pieces.append("Protection not observed; value left unknown instead of guessed.")
    return "; ".join(pieces)

def _norm_conf(raw) -> float:
    try:
        v = float(raw)
        return v * 100.0 if v <= 1.0 else v
    except (TypeError, ValueError):
        return 0.0

def _fmt_pct(raw, default: str = "—") -> str:
    """Format a probability/percentage value for reporting."""
    try:
        return f"{_norm_conf(raw):.1f}%"
    except Exception:
        return default

def _fmt_mse(raw, default: str = "N/A") -> str:
    """Format Autoencoder reconstruction error / MSE without treating it as a percentage."""
    try:
        if raw is None or str(raw).strip() == "":
            return default
        return f"{float(raw):.6f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        return default

def _first_present(d: dict, *keys, default=None):
    """Return the first non-empty value from a dict."""
    for k in keys:
        v = d.get(k)
        if v is not None and str(v).strip() != "":
            return v
    return default

def _fmt_feature_support(raw, default: str = "28/55") -> str:
    """Normalise feature support values that may be stored as tuple/dict/string."""
    if isinstance(raw, dict):
        used = raw.get("used") or raw.get("available") or raw.get("support") or raw.get("matched")
        total = raw.get("total") or raw.get("expected") or raw.get("max")
        if used is not None and total is not None:
            return f"{used}/{total}"
    if isinstance(raw, (list, tuple)) and len(raw) >= 2:
        return f"{raw[0]}/{raw[1]}"
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    return default

def _fmt_coverage(raw, default: str = "36/55 (65.45%)") -> str:
    """Normalise CIC semantic export coverage values."""
    if isinstance(raw, dict):
        used = raw.get("used") or raw.get("covered") or raw.get("matched")
        total = raw.get("total") or raw.get("expected") or raw.get("max")
        pct = raw.get("pct") or raw.get("percent") or raw.get("percentage")
        if used is not None and total is not None:
            if pct is not None:
                try:
                    pct_f = float(pct)
                    if pct_f <= 1.0:
                        pct_f *= 100.0
                    return f"{used}/{total} ({pct_f:.2f}%)"
                except Exception:
                    return f"{used}/{total}"
            return f"{used}/{total}"
    if isinstance(raw, (list, tuple)) and len(raw) >= 2:
        used, total = raw[0], raw[1]
        try:
            pct = float(used) / float(total) * 100.0
            return f"{used}/{total} ({pct:.2f}%)"
        except Exception:
            return f"{used}/{total}"
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    return default

def _anomalies_str(val, maxlen: int = 80) -> str:
    if isinstance(val, list):
        s = "; ".join(str(v) for v in val) if val else "—"
    else:
        s = str(val) if val else "—"
    return (s[:maxlen] + "…") if len(s) > maxlen else s

def _clean_dll_path(raw: str) -> str:
    import re
    m = re.match(r'^(.+?\.\w{3})\s+[-\d]', raw or "")
    return m.group(1) if m else (raw or "—")[:60]

def _signed_str(val) -> str:
    if val is True:  return "Yes"
    if val is False: return "No"
    s = str(val).strip().lower()
    if s in ("true",  "yes", "1"): return "Yes"
    if s in ("false", "no",  "0"): return "No"
    return "—"


class PDFReporter:

    @staticmethod
    def generate(session, options: Dict, path: str, fname: str) -> Dict[str, Any]:
        if _HAS_REPORTLAB:
            return PDFReporter._reportlab(session, options, path, fname)
        return PDFReporter._text_fallback(session, path, fname)

    @staticmethod
    def _reportlab(session, options: Dict, path: str, fname: str) -> Dict[str, Any]:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import mm
            from reportlab.lib import colors as rl_colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
            from reportlab.platypus import (
                BaseDocTemplate, Frame, PageTemplate,
                HRFlowable, Image as RLImage,
                NextPageTemplate, PageBreak, Paragraph,
                Spacer, Table, TableStyle,
            )
            from xml.sax.saxutils import escape as _xml_escape
            import re as _re

            # ── Palette ────────────────────────────────────────────────────
            C_NAVY      = rl_colors.HexColor("#1E3A5F")
            C_NAVY_MID  = rl_colors.HexColor("#2D5282")
            C_SKY       = rl_colors.HexColor("#0EA5E9")
            C_GREEN     = rl_colors.HexColor("#16A34A")
            C_GREEN_BG  = rl_colors.HexColor("#F0FDF4")
            C_RED       = rl_colors.HexColor("#DC2626")
            C_RED_BG    = rl_colors.HexColor("#FEF2F2")
            C_AMBER     = rl_colors.HexColor("#D97706")
            C_TEXT      = rl_colors.HexColor("#1E293B")
            C_MUTED     = rl_colors.HexColor("#64748B")
            C_RULE      = rl_colors.HexColor("#CBD5E1")
            C_ROW_ALT   = rl_colors.HexColor("#F8FAFC")
            C_ROW_SUSP  = rl_colors.HexColor("#FEF2F2")
            C_WHITE     = rl_colors.white

            PAGE_W, PAGE_H = A4
            L_MAR = R_MAR = 18 * mm
            T_MAR = 28 * mm
            B_MAR = 22 * mm
            HDR_H = 14 * mm

            # ── Session data ───────────────────────────────────────────────
            ml          = session.ml_result or {}
            extra_ml    = ml.get("extra_features", {}) if isinstance(ml.get("extra_features", {}), dict) else {}
            verdict     = ml.get("verdict", "unknown").upper()

            # Current RAMDetect reporting semantics:
            # - RF suspicious score / final ML score is the score compared with the fixed 0.5 threshold.
            # - Autoencoder reconstruction error is a fused RF input, not a separate verdict percentage.
            rf_raw      = _first_present(ml, "rf_score", "suspicion_score", "display_score", "confidence", default=0)
            final_raw   = _first_present(ml, "display_score", "rf_score", "suspicion_score", "confidence", default=rf_raw)
            rf_sc       = _norm_conf(rf_raw)
            final_sc    = _norm_conf(final_raw)

            ae_mse_raw  = _first_present(
                ml,
                "reconstruction_error", "ae_mse", "autoencoder_mse", "mse",
                default=_first_present(extra_ml, "reconstruction_error", "ae_mse", "autoencoder_mse", "mse")
            )
            ae_mse_txt  = _fmt_mse(ae_mse_raw)

            decision_mode = str(ml.get("decision_mode") or "ML-only RF-AE feature fusion").replace("_", " ")
            fusion_schema = "54 base features + AE MSE = 55 fused RF inputs"
            rf_threshold_txt = "0.5"

            feature_support_txt = _fmt_feature_support(
                _first_present(
                    ml, "ml_decision_feature_support", "decision_feature_support", "feature_support",
                    default=_first_present(extra_ml, "ml_decision_feature_support", "decision_feature_support", "feature_support")
                )
            )
            cic_coverage_txt = _fmt_coverage(
                _first_present(
                    ml, "cic_semantic_export_coverage", "semantic_export_coverage", "cic_coverage",
                    default=_first_present(extra_ml, "cic_semantic_export_coverage", "semantic_export_coverage", "cic_coverage")
                )
            )
            cic_schema_txt = str(
                _first_present(
                    ml, "cic_csv_schema_compatibility", "csv_schema_compatibility",
                    default=_first_present(extra_ml, "cic_csv_schema_compatibility", "csv_schema_compatibility", default="100.00%")
                )
            )
            if cic_schema_txt.replace(".", "", 1).isdigit():
                try:
                    _schema_float = float(cic_schema_txt)
                    cic_schema_txt = f"{_schema_float:.2f}%"
                except Exception:
                    pass

            is_susp     = verdict in ("SUSPICIOUS", "MALICIOUS")
            conf        = final_sc  # Backward-compatible alias for existing report risk/score logic.
            V_COLOR     = C_RED   if is_susp else C_GREEN
            V_BG        = C_RED_BG if is_susp else C_GREEN_BG

            processes   = session.processes   or []
            threads     = session.threads     or []
            dlls        = session.dlls        or []
            handles     = session.handles     or []
            pe_sections = session.pe_sections or []
            injections  = getattr(session, "injections", [])
            combined_pe = list(pe_sections) + [{**inj, "is_suspicious": True} for inj in injections]
            findings    = session.findings or []
            report_only_ransomware_artifacts = collect_report_only_ransomware_artifacts(session)

            def _is_artifact_suspicious(i):
                return (str(i.get("status", "")).lower() in ("suspicious", "malicious")
                        or bool(i.get("is_suspicious", False)))

            # Strong forensic evidence means there is an actual suspicious artifact,
            # not just an ML probability or an unresolved signature flag.
            n_susp_processes = sum(1 for p in processes if _is_artifact_suspicious(p))
            n_susp_threads   = sum(1 for t in threads   if _is_artifact_suspicious(t))
            n_susp_dlls      = sum(1 for d in dlls      if _is_artifact_suspicious(d))
            n_susp_handles   = sum(1 for h in handles   if _is_artifact_suspicious(h))
            n_susp_pe        = sum(1 for pe in combined_pe if _is_artifact_suspicious(pe))
            has_direct_forensic_evidence = bool(
                n_susp_processes or n_susp_handles or n_susp_pe or len(injections)
            )
            ml_only_review = bool(is_susp and not has_direct_forensic_evidence)


            try:
                from ui.bridge.config_bridge import Config
                org = Config.get("reports.organisation", "RAMDetect")
                hdr_txt = Config.get("reports.header_text", "Memory Forensics Report")
            except Exception:
                org = "RAMDetect"
                hdr_txt = "Memory Forensics Report"

            pdf_secs = options.get("pdf_sections", {})
            def _sec(k): return pdf_secs.get(k, True) if pdf_secs else True

            gen_date = datetime.now().strftime("%Y-%m-%d %H:%M")

            # ── Styles ─────────────────────────────────────────────────────
            SS = getSampleStyleSheet()
            def _s(name, **kw):
                return ParagraphStyle(name, parent=SS["Normal"], **kw)

            sty_body   = _s("Bd",  fontSize=9,  textColor=C_TEXT,     spaceAfter=3, leading=14, wordWrap="CJK", splitLongWords=1)
            sty_muted  = _s("Mu",  fontSize=8,  textColor=C_MUTED,    spaceAfter=2, leading=10, wordWrap="CJK", splitLongWords=1)
            # J9C: explanatory note style used by the PE Sections / Injections evidence note.
            # This is presentation-only and has no effect on ML, FeatureMapper, threshold, or verdict logic.
            sty_note   = _s("No",  fontSize=7.8, textColor=C_MUTED,    spaceAfter=4, leading=10, wordWrap="CJK", splitLongWords=1)
            sty_h1_wh  = _s("H1w", fontSize=13, textColor=C_WHITE,    fontName="Helvetica-Bold", spaceAfter=0, leading=16)
            sty_h2     = _s("H2",  fontSize=11, textColor=C_NAVY_MID, fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4, leading=14)
            sty_h3     = _s("H3",  fontSize=10, textColor=C_NAVY,     fontName="Helvetica-Bold", spaceBefore=5, spaceAfter=3, leading=12)

            # Compact table text styles. wordWrap="CJK" lets ReportLab break long paths,
            # hashes, object names, and garbled memory strings inside the cell instead of
            # drawing across neighbouring columns.
            sty_cell   = _s("Ce",  fontSize=7.4, textColor=C_TEXT,  leading=9.2, wordWrap="CJK", splitLongWords=1)
            sty_cell_m = _s("Cm",  fontSize=7.4, textColor=C_MUTED, leading=9.2, wordWrap="CJK", splitLongWords=1)
            sty_cell_r = _s("Cr",  fontSize=7.4, textColor=C_RED,   fontName="Helvetica-Bold", leading=9.2, wordWrap="CJK", splitLongWords=1)
            sty_cell_g = _s("Cg",  fontSize=7.4, textColor=C_GREEN, fontName="Helvetica-Bold", leading=9.2, wordWrap="CJK", splitLongWords=1)
            sty_cell_n = _s("Cn",  fontSize=7.4, textColor=C_NAVY,  fontName="Helvetica-Bold", leading=9.2, wordWrap="CJK", splitLongWords=1)
            sty_cell_a = _s("Ca",  fontSize=7.4, textColor=C_AMBER, fontName="Helvetica-Bold", leading=9.2, wordWrap="CJK", splitLongWords=1)
            sty_cell_b = _s("Cb",  fontSize=7.4, textColor=C_SKY,   fontName="Helvetica-Bold", leading=9.2, wordWrap="CJK", splitLongWords=1)
            sty_bullet = _s("Bu",  fontSize=9,  textColor=C_TEXT,  leftIndent=10, spaceAfter=3, leading=14, wordWrap="CJK", splitLongWords=1)

            def _clean_text_for_pdf(val, maxlen: int | None = None) -> str:
                """Sanitise artifact strings before putting them into ReportLab Paragraphs."""
                if val is None:
                    return "—"
                s = str(val)
                # Flatten table text while keeping it readable.
                s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
                # Remove control characters and collapse repeated spaces.
                s = _re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", " ", s)
                s = _re.sub(r"\s{2,}", " ", s).strip()
                # Collapse long runs of replacement/black-box glyphs from noisy memory strings.
                s = _re.sub(r"[■□�]{4,}", "[garbled memory text]", s)
                s = _re.sub(r"(?:\[garbled memory text\]\s*){2,}", "[garbled memory text] ", s)
                if not s:
                    s = "—"
                if maxlen and len(s) > maxlen:
                    s = s[:maxlen-1].rstrip() + "…"
                return s

            def _p(val, style=None, maxlen: int | None = None):
                """Create a wrapping Paragraph for table cells; keep existing Paragraphs unchanged."""
                if isinstance(val, Paragraph):
                    return val
                txt = _xml_escape(_clean_text_for_pdf(val, maxlen=maxlen))
                return Paragraph(txt, style or sty_cell)

            # ── Table helper ───────────────────────────────────────────────
            def _make_table(data, col_widths, extra=None):
                base = [
                    ("BACKGROUND",    (0, 0), (-1,  0),  C_NAVY),
                    ("TEXTCOLOR",     (0, 0), (-1,  0),  C_WHITE),
                    ("FONTNAME",      (0, 0), (-1,  0),  "Helvetica-Bold"),
                    ("FONTSIZE",      (0, 0), (-1, -1),  7.4),
                    ("TEXTCOLOR",     (0, 1), (-1, -1),  C_TEXT),
                    ("ROWBACKGROUNDS",(0, 1), (-1, -1),  [C_WHITE, C_ROW_ALT]),
                    ("GRID",          (0, 0), (-1, -1),  0.4, C_RULE),
                    ("TOPPADDING",    (0, 0), (-1, -1),  4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1),  4),
                    ("LEFTPADDING",   (0, 0), (-1, -1),  4),
                    ("RIGHTPADDING",  (0, 0), (-1, -1),  4),
                    ("VALIGN",        (0, 0), (-1, -1),  "TOP"),
                ]
                if extra:
                    base += extra
                t = Table(data, colWidths=col_widths, repeatRows=1, splitByRow=1)
                t.setStyle(TableStyle(base))
                return t

            # ── Section header ─────────────────────────────────────────────
            def _sec_hdr(title):
                row = Table([[Paragraph(title, sty_h1_wh)]],
                            colWidths=[PAGE_W - L_MAR - R_MAR])
                row.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), C_NAVY),
                    ("TOPPADDING",    (0,0),(-1,-1), 8),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 8),
                    ("LEFTPADDING",   (0,0),(-1,-1), 10),
                ]))
                return [row, Spacer(1, 6)]

            # ── Header / Footer ────────────────────────────────────────────
            # ── Single page callback — handles cover AND inner pages ───────
            # ── Logo loader ─────────────────────────────────────────────
            _logo_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                "..", "..", "ui", "resources", "photo", "ramdetect.png"
            )
            if not os.path.isfile(_logo_path):
                _logo_path = os.path.join(
                    "ramdetect", "ui", "resources", "photo", "ramdetect.png"
                )

            def _get_logo_buf(size_px: int = 200):
                """Load the RAMDetect logo, remove dark background, crop padding, and return PNG buffer."""
                try:
                    from PIL import Image as PILImage
                    import io as _io

                    img = PILImage.open(_logo_path).convert("RGBA")

                    # Existing logo asset appears to have a dark background/padding.
                    # Make very dark pixels transparent so it sits cleanly on the navy cover.
                    data = img.load()
                    w2, h2 = img.size
                    for y2 in range(h2):
                        for x2 in range(w2):
                            r2, g2, b2, a2 = data[x2, y2]
                            if a2 > 0 and r2 < 70 and g2 < 70 and b2 < 70:
                                data[x2, y2] = (r2, g2, b2, 0)

                    # Crop transparent border; otherwise the logo looks tiny even when the box is large.
                    bbox = img.getchannel("A").getbbox()
                    if bbox:
                        img = img.crop(bbox)

                    img.thumbnail((size_px, size_px), PILImage.LANCZOS)
                    buf = _io.BytesIO()
                    img.save(buf, format="PNG")
                    buf.seek(0)
                    return buf
                except Exception:
                    return None

            _logo_buf_cover  = _get_logo_buf(560)
            _logo_buf_header = _get_logo_buf(120)

            def _on_page(canvas, doc):
                """Use pageTemplate.id — reliable cover vs inner detection."""
                tmpl_id = getattr(getattr(doc, "pageTemplate", None), "id", "Inner")
                is_cover = (tmpl_id == "Cover")

                if is_cover:
                    canvas.saveState()
                    canvas.setFillColor(C_NAVY)
                    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
                    canvas.restoreState()
                    return

                # Inner pages
                canvas.saveState()
                canvas.setFillColor(C_NAVY)
                canvas.rect(0, PAGE_H - HDR_H, PAGE_W, HDR_H, fill=1, stroke=0)

                # Logo + wordmark left
                hdr_logo_drawn = False
                if _logo_buf_header:
                    try:
                        _logo_buf_header.seek(0)
                        logo_sz = HDR_H * 0.72
                        logo_y  = PAGE_H - HDR_H + (HDR_H - logo_sz) / 2
                        canvas.drawImage(
                            _logo_buf_header, L_MAR, logo_y,
                            width=logo_sz, height=logo_sz,
                            mask="auto", preserveAspectRatio=True,
                        )
                        canvas.setFont("Helvetica-Bold", 10)
                        canvas.setFillColor(C_WHITE)
                        canvas.drawString(L_MAR + logo_sz + 3, PAGE_H - HDR_H + 4*mm, "RAMDetect")
                        hdr_logo_drawn = True
                    except Exception:
                        pass
                if not hdr_logo_drawn:
                    canvas.setFont("Helvetica-Bold", 10)
                    canvas.setFillColor(C_WHITE)
                    canvas.drawString(L_MAR, PAGE_H - HDR_H + 4*mm, "RAMDetect")

                # Centre title
                canvas.setFont("Helvetica", 8)
                canvas.setFillColor(rl_colors.HexColor("#93C5FD"))
                canvas.drawCentredString(PAGE_W/2, PAGE_H - HDR_H + 4*mm, hdr_txt)

                # Verdict badge right
                bx = PAGE_W - R_MAR - 32*mm
                by = PAGE_H - HDR_H + 2.5*mm
                canvas.setFillColor(V_COLOR)
                canvas.roundRect(bx, by, 30*mm, 6*mm, radius=1.5*mm, fill=1, stroke=0)
                canvas.setFont("Helvetica-Bold", 8)
                canvas.setFillColor(C_WHITE)
                canvas.drawCentredString(bx + 15*mm, by + 1.8*mm, verdict)

                # Footer
                canvas.setStrokeColor(C_RULE)
                canvas.setLineWidth(0.5)
                canvas.line(L_MAR, B_MAR - 2*mm, PAGE_W - R_MAR, B_MAR - 2*mm)
                canvas.setFont("Helvetica", 7)
                canvas.setFillColor(C_MUTED)
                canvas.drawString(L_MAR, B_MAR - 6*mm,
                    f"Generated: {gen_date}  |  File: {session.dump_filename or '—'}")
                canvas.drawRightString(PAGE_W - R_MAR, B_MAR - 6*mm, f"Page {doc.page}")
                canvas.restoreState()

            # ── Doc setup ──────────────────────────────────────────────────
            cover_frame = Frame(L_MAR, 20*mm,
                                PAGE_W - L_MAR - R_MAR,
                                PAGE_H - 40*mm,
                                id="cover")
            inner_frame = Frame(L_MAR, B_MAR, PAGE_W-L_MAR-R_MAR, PAGE_H-T_MAR-B_MAR, id="inner")

            doc = BaseDocTemplate(path, pagesize=A4,
                                  leftMargin=L_MAR, rightMargin=R_MAR,
                                  topMargin=T_MAR,  bottomMargin=B_MAR)
            doc.addPageTemplates([
                PageTemplate(id="Cover", frames=[cover_frame], onPage=_on_page),
                PageTemplate(id="Inner", frames=[inner_frame], onPage=_on_page),
            ])

            story = [NextPageTemplate("Cover")]

            # ════════════════════════════════════════════════════════════════
            # COVER PAGE
            # ════════════════════════════════════════════════════════════════
            story.append(Spacer(1, 24*mm))

            # Logo image on cover — use PNG with transparent bg, or fall back to text
            if _logo_buf_cover:
                try:
                    _logo_buf_cover.seek(0)
                    logo_img = RLImage(_logo_buf_cover, width=58*mm, height=58*mm)
                    logo_wrap = Table([[logo_img]], colWidths=[PAGE_W - L_MAR - R_MAR])
                    logo_wrap.setStyle(TableStyle([
                        ("ALIGN",  (0,0),(-1,-1), "CENTER"),
                        ("VALIGN", (0,0),(-1,-1), "MIDDLE"),
                    ]))
                    story.append(logo_wrap)
                    story.append(Spacer(1, 7*mm))
                except Exception:
                    pass
            story.append(Paragraph("RAMDetect",
                                   _s("CT", fontSize=32, leading=38, textColor=C_WHITE,
                                      fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=2)))
            story.append(Paragraph("Memory Forensics Analysis Platform",
                                   _s("CS", fontSize=13, leading=18, textColor=rl_colors.HexColor("#93C5FD"),
                                      alignment=TA_CENTER, spaceAfter=0)))
            story.append(Spacer(1, 13*mm))

            # Big verdict badge — no emoji (ReportLab built-in fonts can't render them)
            verdict_icon = "[!]  SUSPICIOUS" if is_susp else "[OK]  CLEAN"
            v_badge = Table([[
                Paragraph(verdict_icon,
                          _s("VB", fontSize=26, leading=32, textColor=V_COLOR,
                             fontName="Helvetica-Bold", alignment=TA_CENTER))
            ]], colWidths=[120*mm])
            v_badge.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), V_BG),
                ("BOX",           (0,0),(-1,-1), 2.5, V_COLOR),
                ("TOPPADDING",    (0,0),(-1,-1), 12),
                ("BOTTOMPADDING", (0,0),(-1,-1), 12),
                ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ]))
            outer_v = Table([[v_badge]], colWidths=[PAGE_W - L_MAR - R_MAR])
            outer_v.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER")]))
            story.append(outer_v)
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph(
                f"Final ML Score: <b>{final_sc:.1f}%</b>",
                _s("VC", fontSize=13, leading=17, textColor=rl_colors.HexColor("#CBD5E1"), alignment=TA_CENTER, spaceAfter=6),
            ))
            story.append(Spacer(1, 10*mm))

            # Cover metadata
            cover_meta = Table([
                ["Memory Dump",          session.dump_filename or "—"],
                ["File Size",            getattr(session,"dump_size_str","—") or "—"],
                ["Analysis Date",        gen_date],
                ["Final ML Score",       f"{final_sc:.1f}%"],
                ["RF Suspicion Score",   f"{rf_sc:.1f}%"],
                ["AE MSE Fusion Input",  ae_mse_txt],
                ["Decision Mode",        "ML-only RF-AE feature fusion"],
                ["Total Findings",       str(len(findings))],
            ], colWidths=[58*mm, 92*mm])
            cover_meta.setStyle(TableStyle([
                ("FONTSIZE",     (0,0),(-1,-1), 9),
                ("FONTNAME",     (0,0),(0,-1),  "Helvetica-Bold"),
                ("TEXTCOLOR",    (0,0),(0,-1),  rl_colors.HexColor("#93C5FD")),
                ("TEXTCOLOR",    (1,0),(1,-1),  C_WHITE),
                ("LINEBELOW",    (0,0),(-1,-2), 0.3, rl_colors.HexColor("#334155")),
                ("TOPPADDING",   (0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                ("LEFTPADDING",  (0,0),(-1,-1), 0),
            ]))
            outer_meta = Table([[cover_meta]], colWidths=[PAGE_W-L_MAR-R_MAR])
            outer_meta.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER")]))
            story.append(outer_meta)
            story.append(Spacer(1, 10*mm))
            story.append(Paragraph(
                "CONFIDENTIAL — For authorised investigator use only",
                _s("Disc", fontSize=8, leading=11, textColor=rl_colors.HexColor("#94A3B8"), alignment=TA_CENTER),
            ))

            story.append(NextPageTemplate("Inner"))
            story.append(PageBreak())

            # ════════════════════════════════════════════════════════════════
            # EXECUTIVE SUMMARY
            # ════════════════════════════════════════════════════════════════
            if _sec("executive_summary"):
                story += _sec_hdr("Executive Summary")

                risk     = "HIGH" if conf >= 80 else "MEDIUM" if conf >= 50 else "LOW"
                risk_col = C_RED if risk=="HIGH" else C_AMBER if risk=="MEDIUM" else C_GREEN
                n_high   = sum(1 for f in findings if str(f.get("severity","")).upper() in ("HIGH","CRITICAL"))
                n_medium = sum(1 for f in findings if str(f.get("severity","")).upper() == "MEDIUM")
                n_low    = sum(1 for f in findings if str(f.get("severity","")).upper() in ("LOW","INFO"))

                summary = (
                    f"This memory dump has been classified as <b>{verdict}</b> with "
                    f"a <b>{final_sc:.1f}%</b> final ML/RF suspicious score "
                    f"against the fixed <b>{rf_threshold_txt}</b> Random Forest threshold "
                    f"(risk level: <b>{risk}</b>). "
                )
                if is_susp and ml_only_review:
                    summary += (f"Analysis identified <b>{len(findings)}</b> finding(s): "
                                f"<b>{n_high}</b> HIGH, <b>{n_medium}</b> MEDIUM, <b>{n_low}</b> LOW. "
                                "No direct high-confidence forensic artifact was confirmed; manual review and baseline comparison are recommended.")
                elif is_susp:
                    summary += (f"Analysis identified <b>{len(findings)}</b> finding(s): "
                                f"<b>{n_high}</b> HIGH, <b>{n_medium}</b> MEDIUM, <b>{n_low}</b> LOW. "
                                "Investigation is recommended.")
                else:
                    if report_only_ransomware_artifacts:
                        summary += (
                            f"The ML classifier did not cross the suspicious threshold; however, "
                            f"<b>{len(report_only_ransomware_artifacts)}</b> report-only ransomware artifact(s) "
                            "were identified for analyst review. These artifacts do not change the final verdict."
                        )
                    else:
                        summary += "No significant malicious indicators were detected."
                story.append(Paragraph(summary, sty_body))
                story.append(Spacer(1, 4))

                if findings:
                    buf_sev = ChartBuilder.severity_breakdown(findings)
                    if buf_sev:
                        story.append(RLImage(buf_sev, width=120*mm, height=42*mm))
                        story.append(Spacer(1, 4))

                story.append(Paragraph("Analysis Metadata", sty_h2))
                meta_data = [
                    ["Field",        "Value"],
                    ["Dump File",    session.dump_filename or "—"],
                    ["File Size",    getattr(session,"dump_size_str","—") or "—"],
                    ["Analysis Date",gen_date],
                    ["Tool Version", "RAMDetect v1.0.0"],
                    ["MD5",          getattr(session,"md5","—") or "—"],
                    ["SHA-256",      getattr(session,"sha256","—") or "—"],
                    ["Risk Level",   risk],
                    ["Decision Logic", "ML-only RF-AE feature fusion"],
                    ["RF Threshold",  rf_threshold_txt],
                    ["Fusion Schema", fusion_schema],
                ]
                story.append(_make_table(meta_data, [60*mm, 110*mm],
                    extra=[("TEXTCOLOR",(1,7),(1,7),risk_col),
                           ("FONTNAME", (1,7),(1,7),"Helvetica-Bold")]))
                story.append(Spacer(1, 6))

            # ════════════════════════════════════════════════════════════════
            # KEY FINDINGS
            # ════════════════════════════════════════════════════════════════
            if _sec("detailed_findings") and findings:
                story += _sec_hdr("Key Findings")
                story.append(Paragraph(
                    f"{len(findings)} finding(s). "
                    "RED = High/Critical · AMBER = Medium · BLUE = Low/Info", sty_muted))
                story.append(Spacer(1, 4))

                find_data = [["Severity", "Category", "Description"]]
                sev_extra = []
                for i, f in enumerate(findings, start=1):
                    sev  = _clean_text_for_pdf(f.get("severity", "info")).upper()
                    cat  = _clean_text_for_pdf(f.get("category", "—"), 36)
                    desc = f.get("description", f.get("title", f.get("message", "")))
                    sev_style = sty_cell_r if sev in ("HIGH", "CRITICAL") else sty_cell_a if sev == "MEDIUM" else sty_cell_b
                    find_data.append([_p(sev, sev_style), _p(cat, sty_cell), _p(desc, sty_cell, 260)])
                    if sev in ("HIGH","CRITICAL"):
                        sev_extra += [("BACKGROUND",(0,i),(-1,i),C_RED_BG)]

                story.append(_make_table(find_data, [24*mm,32*mm,114*mm], extra=sev_extra))
                story.append(Spacer(1, 6))
                story.append(PageBreak())

            # ════════════════════════════════════════════════════════════════
            # ML ANALYSIS
            # ════════════════════════════════════════════════════════════════
            if _sec("ml_analysis"):
                story += _sec_hdr("ML Analysis")

                ml_rows = [
                    ["Output", "Value", "Meaning"],
                    ["Final ML Verdict", verdict, "ML-only Random Forest decision over fused features"],
                    ["Final ML/RF Score", f"{final_sc:.1f}%", "Suspicious probability compared with the fixed RF threshold"],
                    ["RF Threshold", rf_threshold_txt, "Decision boundary remains fixed; not tuned per dump"],
                    ["Autoencoder MSE Fusion Input", ae_mse_txt, "Fused input feature to RF; not a separate verdict"],
                    ["Fusion Schema", fusion_schema, "Current RAMDetect RF-AE feature-fusion architecture"],
                    ["Decision Logic", "ML-only", "No veto rules, clean dampeners, or deterministic verdict overrides"],
                ]
                story.append(_make_table(ml_rows, [55*mm,45*mm,70*mm],
                    extra=[("FONTNAME", (0,1),(-1,1),"Helvetica-Bold"),
                           ("TEXTCOLOR",(0,1),(-1,1),V_COLOR),
                           ("BACKGROUND",(0,1),(-1,1),V_BG)]))
                story.append(Spacer(1, 6))

                arch_rows = [
                    ["Architecture Field", "Current Value"],
                    ["ML Decision Feature Support", feature_support_txt],
                    ["CIC Semantic Export Coverage", cic_coverage_txt],
                    ["CIC CSV Schema Compatibility", cic_schema_txt],
                    ["Dataset", "CIC-MalMem-2022"],
                    ["Runtime Scope", "Post-incident RAM forensics using DumpIt acquisition"],
                ]
                story.append(Paragraph("ML / Feature Architecture", sty_h2))
                story.append(_make_table(arch_rows, [70*mm,100*mm]))
                story.append(Spacer(1, 6))

            # ── Anomaly Distribution ───────────────────────────────────
            # Keep the wording "Anomaly Distribution" to match the user's preferred UI/report label.
            anom_dist = ml.get("anomaly_distribution", {})
            buf3 = None
            if anom_dist:
                buf3 = ChartBuilder.anomaly_pie(
                    float(anom_dist.get("clean", 0)),
                    float(anom_dist.get("suspicious", 0)),
                )

            if buf3:
                story.append(Paragraph("Anomaly Distribution", sty_h2))
                story.append(Paragraph(
                    "Distribution summary from the analysed session; this visualisation does not override the ML verdict.",
                    sty_muted,
                ))
                story.append(RLImage(buf3, width=120*mm, height=90*mm))
                story.append(Spacer(1, 6))

            # ── Feature importance ─────────────────────────────────────
            feat_imp = ml.get("feature_importance", [])
            if feat_imp:
                story.append(Paragraph("Feature Importance", sty_h2))
                buf2 = ChartBuilder.feature_importance(feat_imp)
                if buf2:
                    fi_h = min(110*mm, max(70*mm, len(feat_imp[:10]) * 10 * mm))
                    story.append(RLImage(buf2, width=155*mm, height=fi_h))
                story.append(Spacer(1, 6))

            story.append(PageBreak())

            # ════════════════════════════════════════════════════════════════
            # PROCESS ANALYSIS
            # ════════════════════════════════════════════════════════════════
            if _sec("process_tree") and processes:
                story += _sec_hdr("Process Analysis")

                _pid_tc: dict = {}
                for _t in threads:
                    _pid = str(_t.get("pid", _t.get("PID",""))).strip()
                    if _pid and _pid != "—":
                        _pid_tc[_pid] = _pid_tc.get(_pid,0) + 1

                def _tcount(p):
                    pid = _pick(p,"pid","PID","UniqueProcessId","process_id",default="—")
                    tc  = _pick(p,"threads","thread_count","num_threads",
                                "ActiveThreads","NumberOfThreads","active_threads",
                                "Threads","threadCount","nthreads",default="")
                    if not tc or tc=="—" or not str(tc).strip().lstrip("-").isdigit():
                        tc = str(_pid_tc.get(str(pid),"—"))
                    return tc

                def _flatten(procs):
                    rows = []
                    for p in procs:
                        pname  = _pick(p,"image_name","name","process_name",
                                       "image_file_name","ImageFileName","comm",default="—")
                        pid    = _pick(p,"pid","PID","UniqueProcessId","process_id",default="—")
                        status = str(p.get("status",p.get("Status",""))).lower()
                        anoms  = p.get("anomalies",[])
                        anom_s = "; ".join(str(a) for a in anoms) if isinstance(anoms,list) and anoms else "—"
                        if len(anom_s)>90: anom_s=anom_s[:87]+"…"
                        rows.append([pname,str(pid),_tcount(p),status,anom_s,p])
                        rows.extend(_flatten(p.get("children",[])))
                    return rows

                flat_all = _flatten(processes)
                n_total  = len(flat_all)
                n_susp_p = sum(1 for r in flat_all if r[3] in ("suspicious","malicious"))
                n_orphan = sum(1 for r in flat_all
                               if any("orphan" in str(a).lower() for a in r[5].get("anomalies",[])))
                n_low_conf = sum(1 for r in flat_all if bool(r[5].get("low_confidence_candidate")))

                # Stats strip
                stats_rows = [[
                    Paragraph(f"<b>{n_total}</b><br/><font size='7' color='#64748B'>Total</font>",
                              _s("SC0",fontSize=11,textColor=C_NAVY,alignment=TA_CENTER)),
                    Paragraph(f"<b>{n_susp_p}</b><br/><font size='7' color='#64748B'>Suspicious</font>",
                              _s("SC1",fontSize=11,textColor=C_RED if n_susp_p else C_GREEN,alignment=TA_CENTER)),
                    Paragraph(f"<b>{n_total-n_susp_p}</b><br/><font size='7' color='#64748B'>Clean</font>",
                              _s("SC2",fontSize=11,textColor=C_GREEN,alignment=TA_CENTER)),
                    Paragraph(f"<b>{n_orphan}</b><br/><font size='7' color='#64748B'>Orphans</font>",
                              _s("SC3",fontSize=11,textColor=C_AMBER if n_orphan else C_GREEN,alignment=TA_CENTER)),
                    Paragraph(f"<b>{n_low_conf}</b><br/><font size='7' color='#64748B'>Low-conf.</font>",
                              _s("SC4",fontSize=11,textColor=C_AMBER if n_low_conf else C_GREEN,alignment=TA_CENTER)),
                ]]
                stats_t = Table(stats_rows, colWidths=[33.2*mm]*5)
                stats_t.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), C_ROW_ALT),
                    ("BOX",           (0,0),(-1,-1), 0.5, C_RULE),
                    ("INNERGRID",     (0,0),(-1,-1), 0.5, C_RULE),
                    ("TOPPADDING",    (0,0),(-1,-1), 8),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 8),
                    ("ALIGN",         (0,0),(-1,-1), "CENTER"),
                    ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ]))
                story.append(stats_t)
                story.append(Spacer(1, 8))

                MAX_PROC = 60
                sorted_procs = (
                    [r for r in flat_all if r[3] in ("suspicious","malicious")] +
                    [r for r in flat_all if r[3] not in ("suspicious","malicious")]
                )
                if len(sorted_procs) > MAX_PROC:
                    story.append(Paragraph(
                        f"Showing {MAX_PROC} of {len(sorted_procs)} processes (suspicious first). "
                        "Export to JSON/CSV for the full dataset.", sty_muted))
                    story.append(Spacer(1,4))

                proc_data = [[
                    Paragraph("Process",   sty_cell_n), Paragraph("PID",      sty_cell_n),
                    Paragraph("Threads",   sty_cell_n), Paragraph("Status",   sty_cell_n),
                    Paragraph("Confidence", sty_cell_n), Paragraph("Anomalies", sty_cell_n),
                ]]
                p_extra = []
                for i, row_info in enumerate(sorted_procs[:MAX_PROC], start=1):
                    st = row_info[3]
                    if st in ("suspicious","malicious"):
                        st_p = Paragraph(st.capitalize(), sty_cell_r)
                        p_extra += [("BACKGROUND",(0,i),(-1,i),C_ROW_SUSP)]
                    elif st == "clean":
                        st_p = Paragraph("Clean", sty_cell_g)
                    else:
                        st_p = Paragraph(st.capitalize() if st else "—", sty_cell_m)
                    conf_txt = _j10_conf_label(row_info[5])
                    conf_style = sty_cell_m
                    if "Low-confidence" in conf_txt:
                        conf_style = sty_cell_a
                    elif "High-confidence" in conf_txt:
                        conf_style = sty_cell_g
                    proc_data.append([
                        _p(row_info[0], sty_cell, 48),
                        _p(row_info[1], sty_cell_m),
                        _p(row_info[2], sty_cell_m),
                        st_p,
                        _p(conf_txt, conf_style, 38),
                        _p(row_info[4], sty_cell_m, 95),
                    ])

                story.append(_make_table(proc_data,
                                         [48*mm,14*mm,16*mm,20*mm,30*mm,42*mm],
                                         extra=p_extra))
                story.append(Spacer(1, 6))
                story.append(PageBreak())

            # ════════════════════════════════════════════════════════════════
            # DATA VISUALIZATIONS
            # ════════════════════════════════════════════════════════════════
            if _sec("visualizations"):
                story += _sec_hdr("Data Visualizations")

                def _is_s(i):
                    return (str(i.get("status","")).lower() in ("suspicious","malicious")
                            or i.get("is_suspicious"))

                n_sp = sum(1 for p in processes if _is_s(p))
                n_st = sum(1 for t in threads   if _is_s(t))
                n_sd = sum(1 for d in dlls      if _is_s(d))
                n_sh = sum(1 for h in handles   if _is_s(h))
                n_sp2= sum(1 for pe in combined_pe if _is_s(pe))

                vis_rows = [
                    ["Artifact",              "Total",               "Suspicious / Anomalous"],
                    ["Processes",             str(len(processes)),   str(n_sp)],
                    ["Threads",               str(len(threads)),     str(n_st)],
                    ["DLLs (suspicious)",    str(len(dlls)),        str(n_sd)],
                    ["Handles",               str(len(handles)),     str(n_sh)],
                    ["PE Sections / Injects", str(len(combined_pe)),str(n_sp2)],
                ]
                sc_extra = []
                for i in range(1, len(vis_rows)):
                    val_str = vis_rows[i][2]
                    if val_str.isdigit():
                        col = C_RED if int(val_str) > 0 else C_GREEN
                        sc_extra += [("TEXTCOLOR",(2,i),(2,i),col),
                                     ("FONTNAME", (2,i),(2,i),"Helvetica-Bold")]
                story.append(_make_table(vis_rows, [80*mm,40*mm,50*mm], extra=sc_extra))
                story.append(Spacer(1, 6))

                buf_v = ChartBuilder.artifact_summary(processes, threads, dlls, handles)
                if buf_v:
                    story.append(RLImage(buf_v, width=155*mm, height=100*mm))
                else:
                    story.append(Paragraph("[Artifact chart unavailable]", sty_muted))

                story.append(Spacer(1, 6))

            # ════════════════════════════════════════════════════════════════
            # ARTIFACT TABLES
            # ════════════════════════════════════════════════════════════════
            if _sec("artifact_tables"):
                story += _sec_hdr("Artifact Tables")
                story.append(Paragraph(
                    "Up to 50 rows per table, suspicious entries first. "
                    "Export to JSON/CSV for the complete dataset.", sty_muted))
                story.append(Spacer(1, 6))
                MAX_ART = 50

                # Threads
                if threads:
                    story.append(Paragraph("Thread List", sty_h2))
                    _ts = (
                        [t for t in threads if str(t.get("status","")).lower() in ("suspicious","malicious")] +
                        [t for t in threads if str(t.get("status","")).lower() not in ("suspicious","malicious")]
                    )
                    t_data  = [["TID","PID","State","Priority","Status","Anomalies"]]
                    t_extra = []
                    for i, t in enumerate(_ts[:MAX_ART], start=1):
                        status = str(t.get("status","—")).lower()
                        state  = str(t.get("state_name",t.get("state","—")))[:22]
                        if status in ("suspicious","malicious"):
                            st_p = Paragraph(status.capitalize(), sty_cell_r)
                            t_extra += [("BACKGROUND",(0,i),(-1,i),C_ROW_SUSP)]
                        elif status == "clean":
                            st_p = Paragraph("Clean", sty_cell_g)
                        else:
                            st_p = Paragraph(status.capitalize() if status!="—" else "—", sty_cell_m)
                        t_data.append([
                            _p(t.get("tid","—"), sty_cell_m), _p(t.get("pid","—"), sty_cell_m),
                            _p(state, sty_cell), _p(t.get("priority","—"), sty_cell_m),
                            st_p, _p(_anomalies_str(t.get("anomalies",[]),90), sty_cell_m),
                        ])
                    story.append(_make_table(t_data,
                                             [16*mm,16*mm,34*mm,18*mm,24*mm,62*mm],
                                             extra=t_extra))
                    story.append(Spacer(1, 6))

                # DLLs
                if dlls:
                    story.append(Paragraph("Loaded DLLs", sty_h2))
                    _ds = (
                        [d for d in dlls if d.get("is_suspicious") or str(d.get("status", "")).lower() in ("suspicious", "malicious")] +
                        [d for d in dlls if not (d.get("is_suspicious") or str(d.get("status", "")).lower() in ("suspicious", "malicious"))]
                    )
                    d_data  = [["Name","Path","Signed","Status","Anomalies"]]
                    d_extra = []
                    for d in _ds[:MAX_ART]:
                        is_s_dll = d.get("is_suspicious", False)
                        signed   = _signed_str(d.get("signed"))
                        raw_name = str(d.get("name","")).strip()
                        raw_path = _clean_dll_path(str(d.get("path",""))).strip()
                        if not raw_name or raw_name in ("-","—"):
                            if not raw_path or raw_path in ("-","—"):
                                continue
                        actual_row = len(d_data)
                        d_data.append([
                            _p(raw_name or "—", sty_cell, 42),
                            _p(raw_path or "—", sty_cell_m, 120),
                            Paragraph(signed,
                                      sty_cell_r if signed=="No" else
                                      sty_cell_g if signed=="Yes" else sty_cell_m),
                            Paragraph("Suspicious" if is_s_dll else "Clean",
                                      sty_cell_r if is_s_dll else sty_cell_g),
                            _p(_anomalies_str(d.get("anomalies",[]),70), sty_cell_m),
                        ])
                        if is_s_dll:
                            d_extra += [("BACKGROUND",(0,actual_row),(-1,actual_row),C_ROW_SUSP)]
                    story.append(_make_table(d_data,
                                             [34*mm,68*mm,16*mm,24*mm,28*mm],
                                             extra=d_extra))
                    story.append(Spacer(1, 6))

                # Handles
                if handles:
                    story.append(Paragraph("Handle List", sty_h2))
                    h_data = [["Type","Name","PID","Access Mask"]]
                    for h in handles[:MAX_ART]:
                        name_v = str(h.get("name","—"))
                        if len(name_v)>60: name_v=name_v[:57]+"..."
                        h_data.append([_p(h.get("type","—"), sty_cell, 40), _p(name_v, sty_cell_m, 90),
                                        _p(h.get("pid","—"), sty_cell_m), _p(h.get("access_mask","—"), sty_cell_m)])
                    story.append(_make_table(h_data, [34*mm,92*mm,18*mm,26*mm]))
                    story.append(Spacer(1, 6))

                # PE Sections / Injection Evidence
                if combined_pe:
                    story.append(Paragraph("PE Sections / Injections", sty_h2))
                    story.append(Paragraph(
                        "N/A means the value was not available for that artifact type. "
                        "UNKNOWN means RAMDetect preserved the injection evidence but did not observe "
                        "a reliable memory protection value, so it was not guessed.",
                        sty_note,
                    ))
                    _pes = (
                        [pe for pe in combined_pe
                         if pe.get("is_suspicious") or
                         str(pe.get("status","")).lower() in ("suspicious","malicious")] +
                        [pe for pe in combined_pe
                         if not (pe.get("is_suspicious") or
                                 str(pe.get("status","")).lower() in ("suspicious","malicious"))]
                    )
                    pe_data  = [["Process","Section/Type","Address","Size","Protection","Status"]]
                    pe_extra = []
                    for i, pe in enumerate(_pes[:MAX_ART], start=1):
                        is_s_pe = (pe.get("is_suspicious") or
                                   str(pe.get("status","")).lower() in ("suspicious","malicious"))
                        proc_name = pe.get("process") or pe.get("process_name") or pe.get("name") or "—"
                        section_name = pe.get("section") or pe.get("section_name") or pe.get("type") or "—"
                        note = _artifact_evidence_note(pe)
                        section_text = str(section_name)
                        if note:
                            section_text = f"{section_text} ({note})"
                        pe_data.append([
                            _p(proc_name, sty_cell, 42),
                            _p(section_text, sty_cell_m, 58),
                            _p(_artifact_addr(pe), sty_cell_m, 28),
                            _p(_artifact_size(pe), sty_cell_m, 24),
                            _p(_artifact_protection(pe), sty_cell_m, 30),
                            Paragraph("Suspicious" if is_s_pe else "Clean",
                                      sty_cell_r if is_s_pe else sty_cell_g),
                        ])
                        if is_s_pe:
                            pe_extra += [("BACKGROUND",(0,i),(-1,i),C_ROW_SUSP)]
                    story.append(_make_table(pe_data,
                                             [34*mm,52*mm,26*mm,20*mm,26*mm,24*mm],
                                             extra=pe_extra))
                    story.append(Spacer(1, 6))

                story.append(PageBreak())

            # ════════════════════════════════════════════════════════════════
            # REPORT-ONLY RANSOMWARE ARTIFACTS
            # ════════════════════════════════════════════════════════════════
            if _sec("report_only_artifacts") and report_only_ransomware_artifacts:
                story += _sec_hdr("Report-Only Ransomware Artifacts")
                story.append(Paragraph(
                    "The following artifacts are shown for analyst review only. "
                    "They are not mapped into CIC54 features, do not modify malfind.*, "
                    "and do not affect the final ML verdict.",
                    sty_body,
                ))
                story.append(Spacer(1, 4))

                ro_data = [[
                    Paragraph("Process", sty_cell_n),
                    Paragraph("PID", sty_cell_n),
                    Paragraph("Path", sty_cell_n),
                    Paragraph("Confidence", sty_cell_n),
                    Paragraph("Evidence", sty_cell_n),
                    Paragraph("Verdict Effect", sty_cell_n),
                ]]
                for art in report_only_ransomware_artifacts[:30]:
                    proc_name = art.get("process_name") or os.path.basename(str(art.get("path", ""))) or "—"
                    ro_data.append([
                        _p(proc_name, sty_cell, 32),
                        _p(art.get("pid", "—"), sty_cell_m),
                        _p(art.get("path", "—"), sty_cell_m, 95),
                        _p(f"{float(art.get('report_confidence', 0) or 0):.0f}%", sty_cell_a),
                        _p(art.get("reasons", "—"), sty_cell_m, 150),
                        _p(art.get("verdict_effect", "none"), sty_cell_g),
                    ])

                story.append(_make_table(
                    ro_data,
                    [28*mm, 14*mm, 48*mm, 22*mm, 44*mm, 18*mm],
                    extra=[("BACKGROUND", (0,1), (-1,-1), rl_colors.HexColor("#FFFBEB"))],
                ))
                story.append(Spacer(1, 6))
                story.append(Paragraph(
                    "Recommendation: correlate these process artifacts with disk evidence, file-system timestamps, "
                    "and endpoint logs. Do not treat this section as an ML classification override.",
                    sty_muted,
                ))
                story.append(Spacer(1, 6))

            # ════════════════════════════════════════════════════════════════
            # RECOMMENDATIONS
            # ════════════════════════════════════════════════════════════════
            story += _sec_hdr("Recommendations")

            if is_susp and ml_only_review:
                for heading, bullets in [
                    ("Manual Review Recommended", [
                        "Treat this result as an ML-only review case, not a confirmed incident.",
                        "Compare the feature vector against known-clean Windows 10/11 baseline dumps.",
                        "Review the few parser-level artifacts listed in the report before taking remediation action.",
                        "Do not isolate, terminate, or re-image the host unless independent forensic evidence confirms compromise.",
                    ]),
                    ("Suggested Validation", [
                        "Verify the dump acquisition context and confirm known tools such as DumpIt or OneDrive setup activity.",
                        "Correlate with endpoint security logs and Windows Event Logs only if the host is still available.",
                        "Use this clean-like dump to improve RF/AE calibration and reduce count-heavy Windows 11 false positives.",
                    ]),
                ]:
                    story.append(Paragraph(heading, sty_h2))
                    for b in bullets:
                        story.append(Paragraph(f"→  {b}", sty_bullet))
                    story.append(Spacer(1, 4))
            elif is_susp:
                for heading, bullets in [
                    ("Investigation Actions", [
                        "Preserve the memory dump and related disk evidence before remediation.",
                        "Investigate artifacts flagged as suspicious or malicious in the tables above.",
                        "Correlate suspicious PIDs with Windows Event Logs, EDR telemetry, and network connections.",
                        "Escalate to incident response if direct injection, suspicious handles, persistence, or malicious binaries are confirmed.",
                    ]),
                    ("Further Investigation", [
                        "Submit confirmed suspicious binaries to a sandbox for dynamic analysis.",
                        "Check for persistence: scheduled tasks, registry run keys, services, and startup folders.",
                        "Review neighbouring hosts only if compromise is corroborated by independent evidence.",
                    ]),
                ]:
                    story.append(Paragraph(heading, sty_h2))
                    for b in bullets:
                        story.append(Paragraph(f"→  {b}", sty_bullet))
                    story.append(Spacer(1, 4))
            else:
                if report_only_ransomware_artifacts:
                    story.append(Paragraph("ML verdict is clean, but report-only artifacts require analyst review:", sty_h2))
                    for b in [
                        "Review the report-only ransomware artifact section before closing the case.",
                        "Correlate the suspicious process path with disk evidence and endpoint logs.",
                        "Do not treat the report-only artifact as a verdict override; the ML classification remains clean.",
                        "Use the artifact as a triage lead for manual forensic validation.",
                    ]:
                        story.append(Paragraph(f"→  {b}", sty_bullet))
                else:
                    story.append(Paragraph("System appears clean. Preventative recommendations:", sty_h2))
                    for b in [
                        "Continue scheduled memory forensic scans as part of your security monitoring.",
                        "Maintain up-to-date endpoint detection and response (EDR) coverage.",
                        "Ensure all running software is patched and signatures are current.",
                        "Retain this report as a clean baseline for future comparisons.",
                    ]:
                        story.append(Paragraph(f"→  {b}", sty_bullet))

            story.append(Spacer(1, 8))

            # ════════════════════════════════════════════════════════════════
            # APPENDIX
            # ════════════════════════════════════════════════════════════════
            story += _sec_hdr("Appendix")
            story.append(Paragraph(
                "For the complete artifact dataset (all processes, threads, DLLs, handles), "
                "generate a JSON or CSV export from the RAMDetect Reports page. "
                "The full fused feature vector used for ML-only RF-AE classification is available in the CSV export.",
                sty_body))
            story.append(Spacer(1, 4))
            story.append(Paragraph(
                f"Report generated by RAMDetect v1.0.0 on {gen_date}. "
                "For authorised investigator and academic use only.",
                sty_muted))

            doc.build(story)
            return {"success":True, "path":path, "filename":fname,
                    "size_str":_bytes_str(path), "error":""}

        except Exception as exc:
            return {"success":False, "path":path, "filename":fname,
                    "size_str":"—", "error":str(exc)}

    @staticmethod
    def _text_fallback(session, path: str, fname: str) -> Dict[str, Any]:
        try:
            ml   = session.ml_result or {}
            extra_ml = ml.get("extra_features", {}) if isinstance(ml.get("extra_features", {}), dict) else {}
            rf_raw = _first_present(ml, "rf_score", "suspicion_score", "display_score", "confidence", default=0)
            final_raw = _first_present(ml, "display_score", "rf_score", "suspicion_score", "confidence", default=rf_raw)
            final_sc = _norm_conf(final_raw)
            ae_mse_txt = _fmt_mse(_first_present(
                ml, "reconstruction_error", "ae_mse", "autoencoder_mse", "mse",
                default=_first_present(extra_ml, "reconstruction_error", "ae_mse", "autoencoder_mse", "mse")
            ))
            lines = [
                "RAMDetect Forensic Report", "="*60,
                f"Generated      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Dump file      : {session.dump_filename or 'unknown'}",
                f"Verdict        : {ml.get('verdict','unknown').upper()}",
                f"Final ML Score : {final_sc:.1f}%",
                "Decision logic : ML-only RF-AE feature fusion; threshold fixed at 0.5",
                f"AE MSE input   : {ae_mse_txt}",
                "", "Key Findings", "-"*60,
            ]
            for f in (session.findings or []):
                sev  = str(f.get("severity","info")).upper()
                cat  = str(f.get("category",""))
                desc = str(f.get("description", f.get("title", f.get("message",""))))
                lines.append(f"[{sev}] {cat}: {desc}")
            ro_artifacts = collect_report_only_ransomware_artifacts(session)
            if ro_artifacts:
                lines.extend(["", "Report-Only Ransomware Artifacts", "-"*60])
                for a in ro_artifacts:
                    lines.append(
                        f"[REPORT-ONLY] PID {a.get('pid','?')} {a.get('process_name','')} "
                        f"{a.get('path','')} | confidence={a.get('report_confidence',0)} | "
                        f"verdict_effect={a.get('verdict_effect','none')}"
                    )
            with open(path,"w",encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            return {"success":True,"path":path,"filename":fname,
                    "size_str":_bytes_str(path),"error":""}
        except Exception as exc:
            return {"success":False,"path":path,"filename":fname,
                    "size_str":"—","error":str(exc)}