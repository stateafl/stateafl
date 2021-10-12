#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct prova {
	int test;
	char ciao[10];
	void * p;
	char padding[100];
	int another;
};

void recv(int a, void * p, int b, int c) {}
void send(int a, void * p, int b, int c) {}
void custom_send(int a, char* p) {}
void custom_receive(int a, char* p) {}
//void custom_send(int a, struct prova* p) {}
//void custom_receive(int a, struct prova* p) {}

void set_prova(struct prova * pr) {
	pr->test = rand();
	pr->ciao[0] = 65 + rand() % 26;
	//for(int i=0; i<100; i++) pr->padding[i] = rand();
}

int main(int argc, char *argv[]) {

	FILE * fd = fopen("./test.txt", "w+");
	fwrite("CIAO\n", sizeof(char), 5, fd);
	fclose(fd);

	int a = 2;
	int b = 2;

	int c = a + b;

	printf("a + b = %d\n", c);

	char * p, * q;

	p = malloc(sizeof(char) * 10);

	struct prova qr;
	set_prova(&qr);
	qr.p = p+1;
	qr.another = 13;

	printf("rand: %p %d %c\n", &qr, qr.test, qr.ciao[0]);



	for(int i=0; i<3; i++) {

		struct prova pr;
		set_prova(&pr);

		printf("rand: %d %c\n", pr.test, pr.ciao[0]);



		printf("p = %p\n", p);

		strncpy(p,argv[0],10);
		p[9] += i;


		pr.test = atoi(argv[0]);


		q = malloc(sizeof(char) * 20);

		printf("q = %p\n", q);

		sprintf(q, "%s", argv[0]);

		printf("%s\n", p);
		printf("%s\n", q);

		recv(0, &qr.padding, 100, 0);
		custom_receive(1, (void*)0x1234);

		send(0, NULL, 0, 0);
		custom_send(1, (void*)0x1234);

		free(q);
	}


	free(p);

	return 0;

}

