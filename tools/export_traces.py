"""Export an allowlisted, sanitized snapshot of locally stored visible events.

This utility deliberately does not decrypt encrypted_content or export reasoning,
system/developer messages, session metadata, turn context or world state.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE_SUFFIXES = {
    "root": "01a1e0b9-9cff-7c22-92a7-9477ad7fc62b",
    "audit": "01a1e0ba-1519-7890-a4a1-b640049ee312",
    "core": "01a1e0bb-cc9c-7ea0-89c0-7fe5e0fb70b3",
    "web": "01a1e0bb-fd5f-7401-9ad5-6e415c55c847",
}
SOURCE_DIR = Path.home() / ".codex" / "sessions" / "2026" / "11" / "15"
UUID = re.compile(r"\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", re.I)


def sanitize(text):
    """Mask profiles, account identifiers, credentials and opaque/binary blobs."""
    text = str(text)
    text = re.sub(r"(?i)[a-z]:\\+Users\\+[^\\/\s\"']+", "<PROFILE>", text)
    text = re.sub(r"(?i)[a-z]:/+Users/+[^/\s\"']+", "<PROFILE>", text)
    text = re.sub(r"(?i)EVGENNIY", "<USER>", text)
    text = re.sub(r"Куконен(?:Евгений)?", "<STUDENT>", text, flags=re.I)
    text = re.sub(r"\b(?:sk|sk-proj|sk-svcacct)-[A-Za-z0-9_-]{12,}\b", "<SECRET>", text)
    text = re.sub(r"\b(?:acct|account|user|org|proj)-[A-Za-z0-9_-]{12,}\b", "<ACCOUNT_ID>", text)
    text = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{10,}", r"\1<SECRET>", text)
    text = re.sub(r"data:[a-z0-9.+/-]+;base64,[a-z0-9+/=\s]+", "<BINARY_DATA_OMITTED>", text, flags=re.I)
    text = re.sub(r"\bgAAAA[A-Za-z0-9_=-]{16,}", "<ENCRYPTED_CONTENT_OMITTED>", text)
    text = re.sub(r"[A-Za-z0-9+/_=-]{256,}", "<OPAQUE_OR_BINARY_VALUE_OMITTED>", text)
    # Values here are public test fixtures, still masked in the shared trace.
    for value in ["Demo-Only-2026!", "Test-Only-2026!", "Review-Only-2026!",
                  "Demonstrator-123", "Another-long-password", "Long-password"]:
        text = text.replace(value, "<TEST_PASSWORD>")
    text = re.sub(
        r"(?i)((?:api[_-]?key|access[_-]?token|client[_-]?secret|password|CMS_DEMO_PASSWORD)"
        r"[\"']?\s*[:=]\s*[\"'])([^\"'\r\n]{8,})([\"'])",
        r"\1<SECRET_VALUE>\3", text,
    )
    return UUID.sub("<ID>", text)


def visible_content(content):
    """Retain plaintext content blocks, replacing encrypted/image blocks."""
    if isinstance(content, str):
        return [{"type": "text", "text": sanitize(content)}]
    result = []
    for block in content or []:
        if not isinstance(block, dict):
            continue
        kind = block.get("type", "")
        if kind in {"input_text", "output_text", "text"} and isinstance(block.get("text"), str):
            result.append({"type": "text", "text": sanitize(block["text"])})
        elif kind == "encrypted_content":
            result.append({"type": "omitted", "reason": "Encrypted body is unavailable; no decryption attempted"})
        elif "image" in kind or "audio" in kind or "video" in kind:
            result.append({"type": "omitted", "reason": "Binary media omitted"})
    return result


def serialized(value):
    if isinstance(value, str):
        return sanitize(value)
    return sanitize(json.dumps(value, ensure_ascii=False))


def reads_generated_trace(value):
    """Prevent copying a prior generated JSONL back into its own export."""
    value = str(value)
    if "tools.apply_patch(" in value:
        return False
    direct_read = re.search(
        r"(?:Get-Content|\bcat\b|read_file|readFile)[^\r\n]{0,250}"
        r"traces[\\/][^\r\n]{0,180}\.jsonl", value, re.I
    )
    python_read = (re.search(r"(?:Path|open)\(\s*[rRuUbB]*[\"']traces(?:[\\/]|[\"'])", value)
                   and ".jsonl" in value
                   and any(marker in value for marker in ["read_text", "read_bytes", "readlines", "open("]))
    return bool(direct_read or python_read)


def annotate_event_index():
    """Add verified timestamps and stable event ids to the explanatory fragment."""
    rules = [
        ("root", "Сохранены исходные SPEC", "spec/00-project.md", "custom_tool_call"),
        ("core", "Сгенерировано ядро", "*** Add File: ../Автоматизация проектирования интернет-приложений/cms/core.py", "custom_tool_call"),
        ("core", "Первый прогон 38 тестов", "Ran 38 tests", "custom_tool_call_output"),
        ("core", "Исправлен сервисный get", "def _get(self, identifier)", "custom_tool_call"),
        ("core", "Повторный прогон 40 тестов", "Ran 40 tests", "custom_tool_call_output"),
        ("root", "Исправлена проверка регистра пути", "casefold", "custom_tool_call"),
        ("audit", "Адресная перепроверка", "test_core.CoreTests.test_39", "custom_tool_call"),
    ]
    rows = []
    moscow = timezone(timedelta(hours=3))
    for alias, label, needle, kind in rules:
        records = [json.loads(line) for line in (ROOT / "traces" / (alias + "-session.jsonl")).read_text(encoding="utf-8").splitlines()]
        event = next((e for e in records if e["kind"] == kind and needle in json.dumps(e, ensure_ascii=False)), None)
        if not event or not event.get("timestamp"):
            continue
        stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).astimezone(moscow)
        rows.append(f"| {stamp.strftime('%d.%m.%Y %H:%M:%S')} | {alias} | {label} | `{event['event_id']}` в `{alias}-session.jsonl` |")
    target = ROOT / "traces" / "annotated.md"
    source = target.read_text(encoding="utf-8").split("\n<!-- EVENT_INDEX -->", 1)[0]
    section = ("\n<!-- EVENT_INDEX -->\n\n## Проверенные номера событий\n\n"
               "Время приведено по Москве UTC+3 и взято из исходных событий; строки добавляются только при найденном совпадении.\n\n"
               "| Время | Ветка | Событие | Точное место в экспорте |\n"
               "| --- | --- | --- | --- |\n" + "\n".join(rows) + "\n")
    target.write_text(source + section, encoding="utf-8")


def export_one(alias, suffix):
    matches = list(SOURCE_DIR.glob("*" + suffix + ".jsonl"))
    if len(matches) != 1:
        raise ValueError(f"Expected one session source for {alias}; got {len(matches)}")
    source = matches[0]
    snapshot = source.read_bytes()
    parsed, skipped = [], Counter()
    source_meta_id, request_verified = None, False
    for raw in snapshot.decode("utf-8").splitlines():
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            skipped["incomplete_or_invalid_snapshot_line"] += 1
            continue
        payload = event.get("payload", {})
        if event.get("type") == "session_meta":
            source_meta_id = payload.get("id")
        if event.get("type") != "response_item":
            skipped["non_response_item"] += 1
            continue
        if payload.get("type") == "message" and payload.get("role") == "user":
            raw_text = serialized(payload.get("content", []))
            request_verified |= "Автоматизация проектирования интернет-приложений" in raw_text
        parsed.append((event.get("timestamp"), payload))
    if source_meta_id != SOURCE_SUFFIXES["root"] or not request_verified:
        raise ValueError(f"Session identity/request check failed for {alias}")
    call_ids, omitted_calls = {}, set()
    output = []
    counts = Counter()

    def mapped_call(value):
        if value not in call_ids:
            call_ids[value] = f"C{len(call_ids) + 1:04d}"
        return call_ids[value]

    for timestamp, payload in parsed:
        kind = payload.get("type")
        item = {"timestamp": timestamp, "kind": kind}
        if kind == "message":
            role, phase = payload.get("role"), payload.get("phase", payload.get("channel"))
            if role not in {"user", "assistant"} or phase in {"analysis", "reasoning"}:
                skipped["non_visible_message"] += 1
                continue
            item.update(role=role, phase=phase, content=visible_content(payload.get("content")))
        elif kind == "agent_message":
            # These records are explicit inter-agent messages, not reasoning items.
            if payload.get("phase", payload.get("channel")) in {"analysis", "reasoning"}:
                skipped["non_visible_agent_message"] += 1
                continue
            item.update(author=sanitize(payload.get("author", "")),
                        recipient=sanitize(payload.get("recipient", "")),
                        content=visible_content(payload.get("content")))
        elif kind in {"function_call", "custom_tool_call"}:
            call = payload.get("call_id", "")
            value = payload.get("arguments", payload.get("input", ""))
            item.update(call_id=mapped_call(call), name=sanitize(payload.get("name", "")),
                        namespace=sanitize(payload.get("namespace", "")))
            if reads_generated_trace(value):
                omitted_calls.add(call)
                item["input"] = "<GENERATED_TRACE_READ_OMITTED_TO_PREVENT_RECURSION>"
            else:
                item["input"] = serialized(value)
        elif kind in {"function_call_output", "custom_tool_call_output"}:
            call = payload.get("call_id", "")
            item["call_id"] = mapped_call(call)
            item["output"] = ("<GENERATED_TRACE_READ_OUTPUT_OMITTED>" if call in omitted_calls
                              else serialized(payload.get("output", "")))
        else:
            skipped["non_allowlisted_response_type:" + str(kind)] += 1
            continue
        if not item.get("content", [True]):
            skipped["empty_visible_content"] += 1
            continue
        item["event_id"] = f"{alias}-{len(output) + 1:05d}"
        output.append(item)
        counts[kind] += 1
    target = ROOT / "traces" / (alias + "-session.jsonl")
    target.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in output), encoding="utf-8")
    return {"alias": alias, "target": "traces/" + target.name,
            "source_bytes_at_snapshot": len(snapshot), "source_sha256": hashlib.sha256(snapshot).hexdigest(),
            "identity_check": "Exact filename suffix, inherited root metadata and matching visible user task",
            "exported_events": len(output), "types": dict(counts), "omitted": dict(skipped),
            "export_sha256": hashlib.sha256(target.read_bytes()).hexdigest()}


def make_journal():
    """Actual bounded technical iterations, not a fabricated semester diary."""
    rows = [
        ("00-spec", 1, "Codex", "Зафиксировать модель, границы, интерфейсы и критерии до генерации.", "auto_accept", "SPEC 00–03 сохранены до реализации.", ["spec/00-project.md", "spec/01-core.md", "spec/02-web.md", "spec/03-harness.md"]),
        ("01-core-generation", 2, "Codex core agent", "Реализовать ядро, схемы, миграции и содержательные тесты по SPEC 01.", "auto_rework", "Первый прогон 38 тестов прошёл; последующий аудит обнаружил отсутствие actor в служебном get, потребовалась доработка.", ["core.py", "tests/test_core.py", "evidence/review.md"]),
        ("02-web-generation", 4, "Codex web agent", "Реализовать WSGI-панель и публичную часть по согласованному API.", "auto_rework", "Потребовалось согласовать явный actor, права переходов и предел description с ядром.", ["web.py", "tests/test_web.py", "evidence/review.md"]),
        ("03-guard-generation", 1, "Codex", "Создать ограниченную оболочку инструментов и шесть начальных отрицательных тестов.", "auto_rework", "Базовые проверки созданы; независимый аудит позже нашёл обход .ENV по регистру Windows.", ["harness/guard.py", "tests/test_harness.py", "harness/history.md"]),
        ("04-command-cleanup-fix", 1, "Codex", "Исправить очистку временной SQLite-базы при выполнении проектной команды на Windows.", "auto_accept", "Закрытие соединения перед очисткой устранило Win32-ошибку; сохранены реальные повторные протоколы.", ["harness/commands.py", "evidence/commands"]),
        ("05-free-prompt", 2, "Codex audit agent", "Добавь для нашей учебной CMS тип объявлений с местом и датой проведения.", "auto_reject", "Полученная JSON Schema не соответствует контракту label/fields; 0 из 6 критериев, ядро отклонило её.", ["harness/experiment/free.json", "evidence/experiment.json"]),
        ("06-spec-prompt", 2, "Codex audit agent", "Сгенерировать тот же тип с точным контрактом label/fields и ограничениями полей.", "auto_accept", "6 из 6 критериев; ядро приняло схему. Опыт последовательный, B видел A.", ["harness/experiment/spec.json", "harness/experiment/README.md", "evidence/experiment.json"]),
        ("07-independent-audit", 5, "Codex independent audit agent", "Воспроизвести отрицательные сценарии защиты без изменения кода реализации.", "auto_accept", "Независимая проверка выявила дефекты get и .ENV; дана техническая рекомендация исправить.", ["evidence/review.md", "traces/audit-session.jsonl"]),
        ("08-service-read-fix", 2, "Codex core agent", "Разделить внутреннее чтение и get с проверкой actor; добавить отрицательные тесты.", "auto_accept", "Добавлены проверки анонима и автора чужого черновика; 40 core-тестов прошли.", ["core.py", "tests/test_core.py", "evidence/review.md"]),
        ("09-guard-casefold-fix", 1, "Codex", "Нормализовать регистр и проверять исходный и разрешённый пути.", "auto_accept", ".ENV и .ENV.local блокируются; недоступный на Windows опыт с symlink явно отмечен как пропущенный.", ["harness/guard.py", "tests/test_harness.py", "harness/history.md", "evidence/review.md"]),
        ("10-web-contract-fix", 3, "Codex web agent", "Передать actor, согласовать права переходов и maxlength description с сервисом.", "auto_accept", "Прямой WSGI-сценарий подтвердил вход, правку, переход и предел 300/301 символ.", ["web.py", "tests/test_web.py", "evidence/review.md"]),
        ("11-env-loader", 1, "Codex", "Загрузить только CMS-настройки из .env без выполнения shell и вывода значений.", "auto_accept", "Добавлен whitelist-loader с приоритетом уже заданных переменных среды. Настоящий .env при подготовке трасс не читался.", ["app.py"]),
        ("12-defense", 5, "Codex core agent", "Подготовить ответы на все контрольные вопросы двух заданий по реальному коду.", "auto_accept", "Созданы ответы на 15 вопросов ЛР и 14 ПР; личные действия студента не выдуманы.", ["DEFENSE.md"]),
        ("13-repeat-audit", 5, "Codex independent audit agent", "Повторно проверить исправления get, guard, actor и maxlength.", "auto_accept", "Адресный прогон: 11 тестов, 10 прошли, 1 пропущен; отдельный WSGI-сценарий прошёл. Блокировка HTTP-сокетов аудитора раскрыта.", ["evidence/review.md"]),
        ("14-visible-trace-export", 5, "Codex core agent", "Экспортировать разрешённые видимые события, аннотации, реальный журнал и производные метрики.", "auto_accept", "Снимок исключает скрытые данные и ciphertext; полнота и ограничения описаны отдельно.", ["tools/export_traces.py", "traces/README.md", "traces/manifest.json", "traces/annotated.md"]),
    ]
    journal = {"date": "2026-11-15", "unit": "technical_iteration", "acceptance": "Automated technical assessment only; no student or teacher acceptance is implied",
               "limitations": "One actual working session. No invented 25-iteration history. Existing artifacts prove outcomes; traces preserve available visible actions.",
               "iterations": []}
    for ident, stage, tool, prompt, result, reason, evidence in rows:
        missing = [p for p in evidence if not (ROOT / p).exists()]
        if missing:
            raise ValueError(f"Missing evidence for {ident}: {missing}")
        journal["iterations"].append({"id": ident, "stage": stage, "tool": tool, "prompt": prompt,
                                       "result": result, "reason": reason, "evidence": evidence})
    path = ROOT / "evidence" / "ai-journal.json"
    path.write_text(json.dumps(journal, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    aggregate = Counter(row["result"] for row in journal["iterations"])
    stages = []
    for stage in range(1, 6):
        selected = [r for r in journal["iterations"] if r["stage"] == stage]
        counts = Counter(r["result"] for r in selected)
        stages.append({"stage": stage, "iterations": len(selected), "results": dict(counts),
                       "accept_share": round(counts["auto_accept"] / len(selected), 4) if selected else None})
    total = len(rows)
    metrics = {"source": "evidence/ai-journal.json", "unit": "technical_iteration", "total_iterations": total,
               "results": dict(aggregate), "shares": {k: round(v / total, 4) for k, v in aggregate.items()},
               "by_lab_stage": stages,
               "not_measured": ["Student acceptance", "Semester history", "Generated/accepted/rewritten source-line shares", "Manual time savings", "Independent model performance"],
               "interpretation": "Acceptance labels describe technical review of actual bounded steps. Generation steps later reworked remain rework; fixes are separate steps. Stages are logical work packages, not time periods."}
    (ROOT / "evidence" / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    (ROOT / "traces").mkdir(exist_ok=True)
    manifest = {"snapshot_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "scope": "All allowlisted locally available visible events at the snapshot, sanitized",
                "inherited_prefix": "Fork files include the inherited root history; do not sum event counts as independent iterations",
                "sources": [export_one(alias, suffix) for alias, suffix in SOURCE_SUFFIXES.items()]}
    (ROOT / "traces" / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    annotate_event_index()
    make_journal()
    print(json.dumps({"exported_events": {s["alias"]: s["exported_events"] for s in manifest["sources"]},
                      "journal_iterations": 15, "manifest": "traces/manifest.json"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
