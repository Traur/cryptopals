s=1
c=8

.PHONY: clean
clean:
	autopep8 -r -d .
	autopep8 -r -i .

run:
	python3 Set$(s)Challenge$(c).py

init:
	export PYTHONPATH=:$(shell echo $$PYTHONPATH):$(shell pwd)/libs
