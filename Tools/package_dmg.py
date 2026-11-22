#!/usr/bin/env python3
"""Package an existing signed app for drag-to-Applications installation."""

import argparse
import hashlib
from pathlib import Path
import plistlib
import subprocess
import tempfile


APP_NAME = "局域网代理共享器"
BUNDLE_ID = "com.local.lansharer"
INSTALL_NOTES = f"""+{APP_NAME}适用于 Apple 芯片 Mac，系统要求 macOS 14 或更高版本。

1. 打开 DMG，把“{APP_NAME}”拖到 Applications（应用程序）。
2. 从“应用程序”打开。这个版本未经过 Apple 公证。
3. 若系统提示无法验证开发者，关闭提示，再前往“系统设置 > 隐私与安全性”。
   确认安装包来自官方 Release 后，找到此应用的提示，点按“仍要打开”并按提示确认。
   “仍要打开”通常在尝试打开应用后出现。

开启共享时，macOS 会另行请求管理员授权。
Apple 安装说明：https://support.apple.com/zh-cn/102445
"""


def verify_signature(app: Path) -> None:
    subprocess.run(
        ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    app = args.app.resolve(strict=True)
    output = args.output.absolute()
    if app.name != APP_NAME + ".app" or not app.is_dir():
        parser.error(f"--app must specify {APP_NAME}.app")
    if output.suffix != ".dmg" or output.exists() or output.is_symlink():
        parser.error("--output must specify a new .dmg file")
    with (app / "Contents" / "Info.plist").open("rb") as info:
        if plistlib.load(info).get("CFBundleIdentifier") != BUNDLE_ID:
            parser.error(f"--app must have bundle identifier {BUNDLE_ID}")

    verify_signature(app)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="networksharer-dmg-", dir="/private/tmp") as temp:
        stage = Path(temp) / "stage"
        stage.mkdir()
        copy = stage / app.name
        subprocess.run(["/usr/bin/ditto", str(app), str(copy)], check=True)
        verify_signature(copy)
        (stage / "Applications").symlink_to("/Applications")
        (stage / "安装说明.txt").write_text(INSTALL_NOTES, encoding="utf-8")
        subprocess.run(
            [
                "/usr/bin/hdiutil", "create", "-quiet", "-format", "UDZO",
                "-volname", APP_NAME, "-srcfolder", str(stage), str(output),
            ],
            check=True,
        )

    print("DMG:", output)
    print("SHA-256:", sha256(output))


if __name__ == "__main__":
    main()
