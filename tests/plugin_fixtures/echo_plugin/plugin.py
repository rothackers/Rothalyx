STATE = {
    "name": "",
    "before": 0,
    "program": 0,
    "ai": 0,
    "security": 0,
    "functions": 0,
    "output_path": "",
}


def on_startup(info):
    STATE["name"] = info.get("name", "")
    STATE["output_path"] = info.get("env", {}).get("ZARA_PLUGIN_OUT", "")


def before_binary_analyzed(context):
    summary = context.get("summary", {})
    STATE["before"] = int(summary.get("function_count", 0))


def on_program_analyzed(program):
    STATE["program"] = int(program.get("summary", {}).get("function_count", 0))


def on_function_analyzed(function):
    if function.get("decompiled"):
        STATE["functions"] += 1


def on_binary_analyzed(summary):
    output_path = STATE["output_path"]
    if not output_path:
        raise RuntimeError("ZARA_PLUGIN_OUT is not set")

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(
            f"{summary['format']}|{summary['function_count']}|{summary['import_count']}"
            f"|plugin={STATE['name']}|before={STATE['before']}|program={STATE['program']}"
            f"|ai={STATE['ai']}|security={STATE['security']}|functions={STATE['functions']}"
        )


def on_ai_insights(insights):
    STATE["ai"] = len(insights)


def on_security_report(report):
    STATE["security"] = len(report.get("findings", [])) + len(report.get("gadgets", []))
