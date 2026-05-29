# A&D Defense Agent

Python-based defensive agent for collecting logs, detecting suspicious events, and generating simple response reports.

## Run

```bash
python3 -m agent.main --log samples/sample.log --rules rules/default_rules.yml
```

## Structure

- `agent/collector.py` - reads event logs
- `agent/detector.py` - matches events against rules
- `agent/responder.py` - decides defensive actions
- `agent/reporter.py` - prints findings
- `rules/default_rules.yml` - detection rules
- `samples/sample.log` - sample input log
