from pathlib import Path

from pypdf import PdfReader


PDFS = [
    Path(r"D:/ktb/NE5000E V800R025C10SPC500 配置指南/NE5000E V800R025C10SPC500 配置指南 IP业务.pdf"),
    Path(r"D:/ktb/NE5000E V800R025C10SPC500 配置指南/NE5000E V800R025C10SPC500 配置指南 IP路由.pdf"),
    Path(r"D:/ktb/NE5000E V800R025C10SPC500 配置指南/NE5000E V800R025C10SPC500 配置指南 局域网与城域网接入.pdf"),
    Path(r"D:/ktb/NE5000E V800R025C10SPC500 配置指南/NE5000E V800R025C10SPC500 配置指南 接口与链路.pdf"),
    Path(r"D:/ktb/指导手册-eNSP Pro V100R001C00.pdf"),
    Path(r"D:/ktb/NE5000E V800R022C00SPC500 配置指南.pdf"),
]


def main() -> None:
    out_dir = Path("context/replays/vrp_manual_notes")
    out_dir.mkdir(parents=True, exist_ok=True)
    for pdf in PDFS:
        print(f"PDF: {pdf}")
        reader = PdfReader(str(pdf))
        print(f"pages: {len(reader.pages)}")
        chunks = []
        for index, page in enumerate(reader.pages[:35], start=1):
            try:
                text = page.extract_text() or ""
            except Exception as exc:
                text = f"[extract failed: {exc}]"
            chunks.append(f"\n\n===== PAGE {index} =====\n{text[:6000]}")
        out = out_dir / f"{pdf.stem}.toc.txt"
        out.write_text("\n".join(chunks), encoding="utf-8")
        print(f"wrote: {out}")


if __name__ == "__main__":
    main()
