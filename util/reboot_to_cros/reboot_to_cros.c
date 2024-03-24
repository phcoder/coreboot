#include <unistd.h>
#include <sys/io.h>

int main() {
  iopl(3);
  outb(0x77, 0x72);
  outb(0xc1, 0x73);
  execl ("/usr/sbin/shutdown", "shutdown", "-r", "now", NULL);
}
