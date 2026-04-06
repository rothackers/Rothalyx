STATE = {
    "name": "",
    "output_path": "",
}


def on_startup(info):
    STATE["name"] = info.get("name", "")
    STATE["output_path"] = info.get("env", {}).get("ZARA_PLUGIN_OUT", "")


def on_binary_analyzed(summary):
    output_path = STATE["output_path"]
    if not output_path:
        raise RuntimeError("ZARA_PLUGIN_OUT is not set")

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(
            f"marketplace:{STATE['name']}|{summary['format']}|{summary['function_count']}"
        )
