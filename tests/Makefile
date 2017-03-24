
all: rdrand rdseed

clean:
	rm bin/*

rdrand: rdrand.c
	$(CC) $< -o $@ && mv $@ bin/

rdseed: rdseed.c
	$(CC) $< -o $@ && mv $@ bin/
