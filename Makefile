.PHONY: clean clean-cache clean-reports

# make clean (perform all cleanup tasks)
clean: clean-cache clean-reports

# make clean-cache (only want cache cleanup)
clean-cache:
	find . -type d -name "__pycache__" -prune -exec rm -rf {} +
	find . -name ".DS_Store" -delete
	find . -type d -name ".pytest_cache" -prune -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

# make clean-reports (only want to clean reports and normalized data)
clean-reports:
	find reports -maxdepth 1 -type f \( -name "*.json" -o -name "*.jsonl" \) -delete
	find normalized -maxdepth 1 -type f \( -name "*.json" -o -name "*.jsonl" -o -name "*.npy" -o -name "*.index" \) -delete 2>/dev/null || true
