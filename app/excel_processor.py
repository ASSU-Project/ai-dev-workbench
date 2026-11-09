"""Excel (.xlsx) and CSV Batch PII Processor with Structure & Style Preservation.

Uses `openpyxl` to inspect and mask Excel workbooks in-place while preserving
sheets, styles, column widths, and formulas, plus `csv`/`io` for CSV files.
"""

from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Optional, Tuple

import openpyxl
from openpyxl.cell.cell import MergedCell
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from app.engine import MaskingConfig, PresidioMaskingEngine, ReversibleTokenizer


HEADER_ENTITY_HINTS: Dict[str, str] = {
    "ชื่อ": "TH_PERSON_NAME",
    "นามสกุล": "TH_PERSON_NAME",
    "ชื่อ-นามสกุล": "TH_PERSON_NAME",
    "ชื่อสกุล": "TH_PERSON_NAME",
    "ลูกค้า": "TH_PERSON_NAME",
    "ผู้ติดต่อ": "TH_PERSON_NAME",
    "ผู้เอาประกัน": "TH_PERSON_NAME",
    "insurename": "TH_PERSON_NAME",
    "contacname": "TH_PERSON_NAME",
    "contactname": "TH_PERSON_NAME",
    "messengername": "TH_PERSON_NAME",
    "name": "PERSON",
    "full name": "PERSON",
    "first name": "PERSON",
    "last name": "PERSON",
    "customer": "PERSON",
    "บัตรประชาชน": "TH_NATIONAL_ID",
    "เลขบัตร": "TH_NATIONAL_ID",
    "citizen": "TH_NATIONAL_ID",
    "national id": "TH_NATIONAL_ID",
    "thai id": "TH_NATIONAL_ID",
    "เบอร์": "TH_PHONE_NUMBER",
    "โทรศัพท์": "TH_PHONE_NUMBER",
    "มือถือ": "TH_PHONE_NUMBER",
    "phone": "PHONE_NUMBER",
    "mobile": "TH_PHONE_NUMBER",
    "tel": "TH_PHONE_NUMBER",
    "อีเมล": "EMAIL_ADDRESS",
    "email": "EMAIL_ADDRESS",
    "e-mail": "EMAIL_ADDRESS",
    "บัญชี": "TH_BANK_ACCOUNT",
    "ธนาคาร": "TH_BANK_ACCOUNT",
    "bank": "TH_BANK_ACCOUNT",
    "account": "TH_BANK_ACCOUNT",
    "ที่อยู่": "TH_ADDRESS",
    "contactaddress": "TH_ADDRESS",
    "address": "TH_ADDRESS",
    "บัตรเครดิต": "CREDIT_CARD",
    "credit card": "CREDIT_CARD",
    "ทะเบียน": "TH_LICENSE_PLATE",
    "laser": "TH_LASER_ID",
    "หลังบัตร": "TH_LASER_ID",
}


def infer_entity_from_header(header_name: str) -> str:
    """Infer the most likely PII entity type from a column header name."""
    if not header_name:
        return "CUSTOM_CELL"
    lower = str(header_name).strip().lower()
    for keyword, entity in HEADER_ENTITY_HINTS.items():
        if keyword in lower:
            return entity
    return "PII_DATA"


def inspect_tabular_file(
    file_bytes: bytes,
    filename: str,
    max_preview_rows: int = 10,
) -> Dict[str, Any]:
    """Inspect an uploaded .xlsx or .csv file and return sheet metadata, columns, and preview rows."""
    lower_name = filename.lower()
    if lower_name.endswith(".csv") or lower_name.endswith(".tsv"):
        delimiter = "\t" if lower_name.endswith(".tsv") else ","
        text_content = file_bytes.decode("utf-8-sig", errors="replace")
        reader = list(csv.reader(io.StringIO(text_content), delimiter=delimiter))
        headers = reader[0] if reader else []
        data_rows = reader[1:] if len(reader) > 1 else []
        preview = [
            {headers[i] if i < len(headers) else f"Col_{i+1}": (row[i] if i < len(row) else "") for i in range(len(headers))}
            for row in data_rows[:max_preview_rows]
        ]
        return {
            "filename": filename,
            "file_type": "csv",
            "sheets": [
                {
                    "name": "CSV_Data",
                    "columns": headers,
                    "row_count": len(data_rows),
                    "preview_rows": preview,
                }
            ],
        }

    # Excel (.xlsx)
    wb = openpyxl.load_workbook(io.BytesIO(file_bytes), data_only=True)
    sheets_info: List[Dict[str, Any]] = []

    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        rows_iter = list(ws.iter_rows(values_only=True))
        if not rows_iter:
            sheets_info.append(
                {
                    "name": sheet_name,
                    "columns": [],
                    "row_count": 0,
                    "preview_rows": [],
                }
            )
            continue

        raw_headers = rows_iter[0]
        headers = [
            str(h).strip() if h is not None and str(h).strip() != "" else f"Column_{idx+1}"
            for idx, h in enumerate(raw_headers)
        ]
        data_rows = rows_iter[1:]
        preview = []
        for r in data_rows[:max_preview_rows]:
            row_dict = {}
            for idx, col_name in enumerate(headers):
                val = r[idx] if idx < len(r) else None
                row_dict[col_name] = "" if val is None else str(val)
            preview.append(row_dict)

        sheets_info.append(
            {
                "name": sheet_name,
                "columns": headers,
                "row_count": len(data_rows),
                "preview_rows": preview,
            }
        )

    return {
        "filename": filename,
        "file_type": "xlsx",
        "sheets": sheets_info,
    }


def mask_tabular_file(
    file_bytes: bytes,
    filename: str,
    engine: PresidioMaskingEngine,
    config: MaskingConfig,
    selected_sheets: Optional[List[str]] = None,
    selected_columns: Optional[Dict[str, List[str]]] = None,
    force_mask_selected_columns: bool = False,
    include_audit_sheet: bool = False,
    max_preview_rows: int = 25,
    existing_token_map: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Mask PII across an Excel (.xlsx) or CSV (.csv) file.

    Parameters
    ----------
    selected_sheets : Optional[List[str]]
        Sheets to process (None = all sheets).
    selected_columns : Optional[Dict[str, List[str]]]
        Mapping of `sheet_name -> [col_name, ...]` (or `{"*": [col_name, ...]}`).
        If None or empty for a sheet, all columns in that sheet are scanned.
    force_mask_selected_columns : bool
        If True, when a cell in an explicitly selected column has no sub-span matched
        by Presidio NER/regex (e.g. a standalone Thai/English surname or custom ID),
        the entire non-empty cell value is masked using the active MaskingConfig!
    include_audit_sheet : bool
        If True (and file is .xlsx), adds a `_PII_Token_Vault` sheet with reversible token mappings.
    existing_token_map : Optional[Dict[str, str]]
        Optional existing token map so token IDs remain 100% consistent across multiple runs.
    """
    tokenizer = ReversibleTokenizer(existing_map=existing_token_map)
    lower_name = filename.lower()

    total_cells_scanned = 0
    total_cells_masked = 0
    entity_counts: Dict[str, int] = {}
    sheet_previews: Dict[str, List[Dict[str, Any]]] = {}

    def _mask_cell_value(raw_val: Any, col_header: str, is_explicitly_selected_col: bool) -> Tuple[str, bool, List[str]]:
        """Return (masked_string, was_modified, matched_entity_types)."""
        if raw_val is None:
            return "", False, []
        text_val = str(raw_val)
        if not text_val.strip():
            return text_val, False, []
        # Skip Excel formulas
        if text_val.startswith("="):
            return text_val, False, []

        # First run Presidio engine on the cell text
        res = engine.mask_text(text=text_val, config=config, tokenizer=tokenizer)
        if res["total_masked"] > 0:
            matched_types = [d["entity_type"] for d in res["detections"] if d.get("enabled")]
            return res["masked_text"], True, matched_types

        # Second: Try context-assisted detection using column header if header has a hint
        inferred_entity = infer_entity_from_header(col_header)
        if inferred_entity in ("TH_NATIONAL_ID", "TH_BANK_ACCOUNT", "TH_PHONE_NUMBER") and text_val.strip():
            context_probe = f"{col_header}: {text_val}"
            prefix_len = len(f"{col_header}: ")
            probe_detections = engine.analyze_text(
                text=context_probe,
                entities=config.entities,
                score_threshold=config.score_threshold,
            )
            cell_detections = [
                d for d in probe_detections if d.start >= prefix_len
            ]
            if cell_detections:
                # Mask the spans relative to text_val
                out_parts: List[str] = []
                cursor = 0
                matched_types = []
                for d in cell_detections:
                    rel_start = max(0, d.start - prefix_len)
                    rel_end = min(len(text_val), d.end - prefix_len)
                    if rel_end > rel_start:
                        span_str = text_val[rel_start:rel_end]
                        masked_span = engine._transform_single_span(
                            span_text=span_str,
                            entity_type=d.entity_type,
                            config=config,
                            tokenizer=tokenizer,
                        )
                        out_parts.append(text_val[cursor:rel_start])
                        out_parts.append(masked_span)
                        cursor = rel_end
                        matched_types.append(d.entity_type)
                if matched_types:
                    out_parts.append(text_val[cursor:])
                    return "".join(out_parts), True, matched_types

        # Third: If force_mask_selected_columns is enabled and this column was selected,
        # mask the entire cell value directly
        if force_mask_selected_columns and is_explicitly_selected_col:
            masked_whole = engine._transform_single_span(
                span_text=text_val.strip(),
                entity_type=inferred_entity,
                config=config,
                tokenizer=tokenizer,
            )
            return masked_whole, True, [inferred_entity]

        return text_val, False, []

    # Deduplication + Parallel Batch Execution across CPU Workers
    cell_cache: Dict[Tuple[str, str, bool], Tuple[str, bool, List[str]]] = {}
    cache_hits = 0

    def _precompute_unique_cells(unique_keys: List[Tuple[str, str, bool]]) -> None:
        if not unique_keys:
            return
        if len(unique_keys) > 1:
            # Phase 1: Parallel stateless NLP analysis across all CPU workers (populates engine._analysis_cache)
            unique_texts = list(dict.fromkeys(k[0] for k in unique_keys))

            def _warm_cache(txt: str) -> None:
                engine.analyze_text(
                    text=txt,
                    entities=config.entities,
                    score_threshold=config.score_threshold,
                )

            list(engine._executor.map(_warm_cache, unique_texts))

        # Phase 2: Deterministic cell masking & token assignment in exact row/column order
        for k in unique_keys:
            cell_cache[k] = _mask_cell_value(k[0], k[1], k[2])

    def _get_cached_or_mask(text_val: str, col_header: str, is_explicit: bool) -> Tuple[str, bool, List[str]]:
        nonlocal cache_hits
        key = (text_val, col_header, is_explicit)
        if key in cell_cache:
            cache_hits += 1
            return cell_cache[key]
        res = _mask_cell_value(text_val, col_header, is_explicit)
        cell_cache[key] = res
        return res

    if lower_name.endswith(".csv") or lower_name.endswith(".tsv"):
        delimiter = "\t" if lower_name.endswith(".tsv") else ","
        text_content = file_bytes.decode("utf-8-sig", errors="replace")
        rows = list(csv.reader(io.StringIO(text_content), delimiter=delimiter))
        if not rows:
            return {
                "output_bytes": file_bytes,
                "filename": f"masked_{filename}",
                "total_cells_scanned": 0,
                "total_cells_masked": 0,
                "entity_counts": {},
                "sheet_previews": {},
                "token_map": {},
                "workers_used": engine.max_workers,
                "cache_hits": 0,
            }

        headers = rows[0]
        sel_cols_for_csv = None
        if selected_columns:
            sel_cols_for_csv = selected_columns.get("CSV_Data") or selected_columns.get("*")

        # Gather unique cell keys in deterministic row/column order
        unique_set = set()
        unique_csv_keys: List[Tuple[str, str, bool]] = []
        for row in rows[1:]:
            for c_idx, val in enumerate(row):
                col_name = headers[c_idx] if c_idx < len(headers) else f"Col_{c_idx+1}"
                should_scan = (not sel_cols_for_csv) or (col_name in sel_cols_for_csv)
                is_explicit = bool(sel_cols_for_csv and col_name in sel_cols_for_csv)
                if should_scan and val and str(val).strip() and not str(val).startswith("="):
                    key = (str(val), col_name, is_explicit)
                    if key not in unique_set:
                        unique_set.add(key)
                        unique_csv_keys.append(key)

        _precompute_unique_cells(unique_csv_keys)

        output_rows = [headers]
        preview_list: List[Dict[str, Any]] = []

        for r_idx, row in enumerate(rows[1:]):
            new_row = list(row)
            row_before: Dict[str, str] = {}
            row_after: Dict[str, str] = {}
            row_changed_cols: List[str] = []

            for c_idx, val in enumerate(row):
                col_name = headers[c_idx] if c_idx < len(headers) else f"Col_{c_idx+1}"
                row_before[col_name] = val
                should_scan = (not sel_cols_for_csv) or (col_name in sel_cols_for_csv)
                is_explicit = bool(sel_cols_for_csv and col_name in sel_cols_for_csv)

                if should_scan and val and str(val).strip():
                    total_cells_scanned += 1
                    masked_val, modified, m_types = _get_cached_or_mask(str(val), col_name, is_explicit)
                    new_row[c_idx] = masked_val
                    row_after[col_name] = masked_val
                    if modified:
                        total_cells_masked += 1
                        row_changed_cols.append(col_name)
                        for mt in m_types:
                            entity_counts[mt] = entity_counts.get(mt, 0) + 1
                else:
                    row_after[col_name] = val

            output_rows.append(new_row)
            if r_idx < max_preview_rows:
                preview_list.append(
                    {
                        "row_index": r_idx + 1,
                        "before": row_before,
                        "after": row_after,
                        "changed_columns": row_changed_cols,
                    }
                )

        sheet_previews["CSV_Data"] = preview_list
        out_io = io.StringIO()
        writer = csv.writer(out_io, delimiter=delimiter)
        writer.writerows(output_rows)
        out_bytes = out_io.getvalue().encode("utf-8-sig")

        return {
            "output_bytes": out_bytes,
            "filename": f"masked_{filename}",
            "total_cells_scanned": total_cells_scanned,
            "total_cells_masked": total_cells_masked,
            "entity_counts": entity_counts,
            "sheet_previews": sheet_previews,
            "token_map": tokenizer.token_to_original,
            "workers_used": engine.max_workers,
            "cache_hits": max(0, cache_hits - len(unique_set)),
        }

    # Process Excel (.xlsx) while preserving structure & formatting
    wb = openpyxl.load_workbook(io.BytesIO(file_bytes))
    target_sheets = selected_sheets if selected_sheets else list(wb.sheetnames)

    # First pass: collect unique cell tasks in deterministic sheet/row/column order
    unique_xlsx_tasks = set()
    ordered_xlsx_tasks: List[Tuple[str, str, bool]] = []
    sheet_headers_map: Dict[str, List[str]] = {}
    sheet_sel_cols_map: Dict[str, Optional[List[str]]] = {}

    for sheet_name in wb.sheetnames:
        if sheet_name not in target_sheets:
            continue
        ws = wb[sheet_name]
        max_row = ws.max_row or 0
        max_col = ws.max_column or 0
        if max_row < 2 or max_col < 1:
            continue

        headers = []
        for col_idx in range(1, max_col + 1):
            h_val = ws.cell(row=1, column=col_idx).value
            headers.append(
                str(h_val).strip() if h_val is not None and str(h_val).strip() != "" else f"Column_{col_idx}"
            )
        sheet_headers_map[sheet_name] = headers

        sel_cols_for_sheet = None
        if selected_columns:
            sel_cols_for_sheet = selected_columns.get(sheet_name) or selected_columns.get("*")
        sheet_sel_cols_map[sheet_name] = sel_cols_for_sheet

        for row_idx in range(2, max_row + 1):
            for col_idx in range(1, max_col + 1):
                col_name = headers[col_idx - 1]
                should_scan = (not sel_cols_for_sheet) or (col_name in sel_cols_for_sheet)
                if not should_scan:
                    continue
                orig_val = ws.cell(row=row_idx, column=col_idx).value
                if orig_val is None:
                    continue
                orig_str = str(orig_val)
                if orig_str.strip() and not orig_str.startswith("="):
                    is_explicit = bool(sel_cols_for_sheet and col_name in sel_cols_for_sheet)
                    task_key = (orig_str, col_name, is_explicit)
                    if task_key not in unique_xlsx_tasks:
                        unique_xlsx_tasks.add(task_key)
                        ordered_xlsx_tasks.append(task_key)

    # Execute all unique cell analyses in parallel across CPU worker pool + deterministic token assignment
    _precompute_unique_cells(ordered_xlsx_tasks)

    # Second pass: apply precomputed results and build diff preview
    for sheet_name in wb.sheetnames:
        if sheet_name not in sheet_headers_map:
            continue
        ws = wb[sheet_name]
        max_row = ws.max_row or 0
        max_col = ws.max_column or 0
        headers = sheet_headers_map[sheet_name]
        sel_cols_for_sheet = sheet_sel_cols_map[sheet_name]
        preview_list = []

        for row_idx in range(2, max_row + 1):
            row_before = {}
            row_after = {}
            row_changed_cols = []

            for col_idx in range(1, max_col + 1):
                col_name = headers[col_idx - 1]
                cell = ws.cell(row=row_idx, column=col_idx)
                orig_val = cell.value
                orig_str = "" if orig_val is None else str(orig_val)
                row_before[col_name] = orig_str

                should_scan = (not sel_cols_for_sheet) or (col_name in sel_cols_for_sheet)
                is_explicit = bool(sel_cols_for_sheet and col_name in sel_cols_for_sheet)

                if should_scan and orig_val is not None and orig_str.strip() != "":
                    if not orig_str.startswith("="):
                        total_cells_scanned += 1
                        masked_val, modified, m_types = _get_cached_or_mask(
                            orig_str, col_name, is_explicit
                        )
                        if modified:
                            if not isinstance(cell, MergedCell):
                                cell.value = masked_val
                            total_cells_masked += 1
                            row_changed_cols.append(col_name)
                            for mt in m_types:
                                entity_counts[mt] = entity_counts.get(mt, 0) + 1
                            row_after[col_name] = masked_val
                        else:
                            row_after[col_name] = orig_str
                    else:
                        row_after[col_name] = orig_str
                else:
                    row_after[col_name] = orig_str

            if len(preview_list) < max_preview_rows:
                preview_list.append(
                    {
                        "row_index": row_idx - 1,
                        "before": row_before,
                        "after": row_after,
                        "changed_columns": row_changed_cols,
                    }
                )

        sheet_previews[sheet_name] = preview_list

    # Optionally append a Token Vault sheet if requested and tokens exist
    if include_audit_sheet and tokenizer.token_to_original:
        vault_sheet_name = "_PII_Token_Vault"
        if vault_sheet_name in wb.sheetnames:
            del wb[vault_sheet_name]
        vws = wb.create_sheet(title=vault_sheet_name)
        vws.append(["Token", "Original_PII_Value"])
        header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
        header_font = Font(color="FFFFFF", bold=True)
        for col_idx in (1, 2):
            c = vws.cell(row=1, column=col_idx)
            c.fill = header_fill
            c.font = header_font
        for token, orig in tokenizer.token_to_original.items():
            vws.append([token, orig])
        vws.column_dimensions["A"].width = 28
        vws.column_dimensions["B"].width = 42

    out_stream = io.BytesIO()
    wb.save(out_stream)
    out_bytes = out_stream.getvalue()

    return {
        "output_bytes": out_bytes,
        "filename": f"masked_{filename}",
        "total_cells_scanned": total_cells_scanned,
        "total_cells_masked": total_cells_masked,
        "entity_counts": entity_counts,
        "sheet_previews": sheet_previews,
        "token_map": tokenizer.token_to_original,
        "workers_used": engine.max_workers,
        "cache_hits": max(0, cache_hits - len(unique_xlsx_tasks)),
    }


def restore_tabular_file(
    file_bytes: bytes,
    filename: str,
    token_map: Dict[str, str],
) -> Dict[str, Any]:
    """Restore a tokenized Excel (.xlsx) or CSV (.csv) file using a token_map."""
    lower_name = filename.lower()
    total_restored = 0

    if lower_name.endswith(".csv") or lower_name.endswith(".tsv"):
        delimiter = "\t" if lower_name.endswith(".tsv") else ","
        text_content = file_bytes.decode("utf-8-sig", errors="replace")
        restored_text, total_restored = ReversibleTokenizer.restore_text(text_content, token_map)
        return {
            "output_bytes": restored_text.encode("utf-8-sig"),
            "filename": f"restored_{filename}",
            "total_restored": total_restored,
        }

    wb = openpyxl.load_workbook(io.BytesIO(file_bytes))
    # Also check if workbook itself has a _PII_Token_Vault sheet and merge with token_map
    merged_map = dict(token_map or {})
    if "_PII_Token_Vault" in wb.sheetnames:
        vws = wb["_PII_Token_Vault"]
        for row in list(vws.iter_rows(values_only=True))[1:]:
            if row and len(row) >= 2 and row[0] and row[1] is not None:
                merged_map[str(row[0]).strip()] = str(row[1])

    for sheet_name in wb.sheetnames:
        if sheet_name == "_PII_Token_Vault":
            continue
        ws = wb[sheet_name]
        for row in ws.iter_rows():
            for cell in row:
                if cell.value is not None and isinstance(cell.value, str):
                    new_val, count = ReversibleTokenizer.restore_text(cell.value, merged_map)
                    if count > 0:
                        if not isinstance(cell, MergedCell):
                            cell.value = new_val
                        total_restored += count

    out_stream = io.BytesIO()
    wb.save(out_stream)
    return {
        "output_bytes": out_stream.getvalue(),
        "filename": f"restored_{filename}",
        "total_restored": total_restored,
    }


def generate_sample_excel_bytes() -> bytes:
    """Create a rich, realistic multi-sheet Thai + English sample Excel workbook (.xlsx)
    so the user can test Excel uploading and PII masking with 1 click.
    """
    wb = openpyxl.Workbook()
    ws1 = wb.active
    ws1.title = "Customers_TH_EN"

    headers_1 = [
        "Customer_ID",
        "Full_Name (ชื่อ-นามสกุล)",
        "National_ID (บัตรประชาชน)",
        "Phone (เบอร์โทรศัพท์)",
        "Email (อีเมล)",
        "Bank_Account (เลขบัญชี)",
        "Address (ที่อยู่จัดส่ง)",
        "Notes (หมายเหตุ)",
    ]
    ws1.append(headers_1)

    sample_rows_1 = [
        [
            "CUST-001",
            "นายสมชาย ใจดีมาก",
            "1-1005-01234-56-7",
            "081-234-5678",
            "somchai.jaidee@company.co.th",
            "123-4-56789-0",
            "บ้านเลขที่ 99/12 หมู่ 4 ต.คลองหนึ่ง อ.คลองหลวง จ.ปทุมธานี 12120",
            "ลูกค้า VIP ติดต่อคุณสมชาย โทร 081-234-5678 หรือหลังบัตร ME0-1234567-89",
        ],
        [
            "CUST-002",
            "นางสาววิภาดา ศรีสุวรรณ",
            "3-1012-00456-78-1",
            "092-876-5432",
            "wipada.sri@gmail.com",
            "456-7-89012-3",
            "เลขที่ 45 ซอยสุขุมวิท 24 แขวงคลองตัน เขตคลองเตย กรุงเทพมหานคร 10110",
            "ทะเบียนรถ 1กข 4567ชำระผ่านบัตรเครดิต 4532-0151-1283-0366",
        ],
        [
            "CUST-003",
            "Mr. Johnathan Edward Smith",
            "1100501234567",
            "+66 89 111 2233",
            "john.smith@globalcorp.com",
            "789-0-12345-6",
            "120 Silom Road, Bang Rak, Bangkok 10500",
            "Contact John Smith at john.smith@globalcorp.com or IP 192.168.10.45",
        ],
        [
            "CUST-004",
            "พญ.กมลชนก รัตนโชติ",
            "1-5099-00123-45-2",
            "065-432-1098",
            "dr.kamonchanok@hospital.or.th",
            "901-2-34567-8",
            "บ้านเลขที่ 188/5 ถนนนิมมานเหมินท์ ต.สุเทพ อ.เมือง จ.เชียงใหม่ 50200",
            "ผู้ติดต่อสำรอง นายสมชาย ใจดีมาก โทร 02-345-6789",
        ],
    ]

    for row in sample_rows_1:
        ws1.append(row)

    # Style header row
    header_fill = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid")
    header_font = Font(color="FFFFFF", bold=True, size=11)
    for col_idx in range(1, len(headers_1) + 1):
        cell = ws1.cell(row=1, column=col_idx)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")
        ws1.column_dimensions[get_column_letter(col_idx)].width = 26

    # Second Sheet: HR / Payroll Sample
    ws2 = wb.create_sheet(title="HR_Support_Tickets")
    headers_2 = ["Ticket_ID", "Reporter", "Incident_Summary", "Server_IP"]
    ws2.append(headers_2)
    ws2.append(
        [
            "TCK-101",
            "คุณธนกร วงศ์สวัสดิ์",
            "ลูกค้าแจ้งเปลี่ยนเบอร์จาก 081-234-5678 เป็น 099-112-3344 และอีเมล thanakorn.w@example.com",
            "10.24.88.19",
        ]
    )
    ws2.append(
        [
            "TCK-102",
            "Alice Wonderland",
            "Refund requested to KBANK account 123-4-56789-0 for Alice Wonderland (SSN 123-45-6789)",
            "172.16.0.104",
        ]
    )
    for col_idx in range(1, len(headers_2) + 1):
        cell = ws2.cell(row=1, column=col_idx)
        cell.fill = header_fill
        cell.font = header_font
        ws2.column_dimensions[get_column_letter(col_idx)].width = 30

    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()
