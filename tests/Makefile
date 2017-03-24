BINS := rdrand rdseed

all: $(BINS)

clean:
	-rm $(BINS)

%: %.c
	$(CC) $< -o $@
