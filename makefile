s=1
c=7

.PHONY: clean
clean:
	autopep8 -r -i .

run:
	python3 Set$(s)Challenge$(c).py
