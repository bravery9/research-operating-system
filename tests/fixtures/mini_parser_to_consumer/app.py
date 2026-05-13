import zipfile
from pathlib import Path
from urllib.parse import urlparse as parse

import yaml
from flask import render_template


def preview_archive(bundle_path, config_text):
    with zipfile.ZipFile(bundle_path) as archive:
        archive.extractall("/tmp/inbox")

    settings = yaml.safe_load(config_text)
    parsed_name = parse(settings["template_name"])
    output_path = Path("/tmp/inbox") / settings["output_name"]

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(str(parsed_name))

    return render_template(parsed_name, settings=settings)
