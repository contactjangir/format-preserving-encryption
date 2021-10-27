
.PHONY = all clean

all:
	gcc fpe.c -lm -lcrypto -o ram_fpe

clean:
	rm ram_fpe

