#include <iostream>
#include <string.h>
#include <stdio.h>

void send() {}
void recv() {}

class MyClass {

  public:
    void print() { std::cout << m_stringa << std::endl; }
    MyClass(int d, char * s) { m_int = d; m_stringa = s; std::cout << "Constructor!" << std::endl; }

  private:
    int m_int;
    char * m_stringa;
};

int main() {

  char * stringa = new char[10];

  strcpy(stringa, "ciao");

  MyClass * x = new MyClass(1,stringa);

  x->print();

  printf("x = %p\n", x);
  printf("stringa = %p\n", stringa);

  recv();
  send();

  delete x;
  delete [] stringa;

}
