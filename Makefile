
default: all

all:

runtests:
	./wvtest.py $(wildcard t/t*.py)

test:
	./wvtestrun $(MAKE) runtests

clean:
	rm -f *~ *.pyc \
		t/*.pyc t/*~
