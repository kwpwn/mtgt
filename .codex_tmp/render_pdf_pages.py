import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "pdf_translate_deps"))

import fitz  # type: ignore


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pdf", type=Path)
    parser.add_argument("out_dir", type=Path)
    parser.add_argument("--pages", nargs="+", type=int, required=True, help="1-based page numbers")
    parser.add_argument("--zoom", type=float, default=1.6)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    doc = fitz.open(str(args.pdf))
    matrix = fitz.Matrix(args.zoom, args.zoom)
    stem = args.pdf.stem
    for page_no in args.pages:
        page = doc[page_no - 1]
        pix = page.get_pixmap(matrix=matrix, alpha=False)
        out = args.out_dir / f"{stem}_p{page_no:03d}.png"
        pix.save(str(out))
        print(out)


if __name__ == "__main__":
    main()
