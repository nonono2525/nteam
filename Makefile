.PHONY: check push

check:
	python -c "from pathlib import Path; compile(Path('attack/main (7).py').read_text(encoding='utf-8'), 'attack/main (7).py', 'exec'); compile(Path('attack_agent/main.py').read_text(encoding='utf-8'), 'attack_agent/main.py', 'exec'); print('ok')"

push: check
	git add attack attack_agent Makefile
	git diff --cached --quiet || git commit -m "Update attack agent"
	git push origin main
