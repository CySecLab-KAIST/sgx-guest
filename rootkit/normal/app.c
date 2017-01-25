#include <stdio.h>
int key = 0xdeadbeef;
int main(){
        printf("my key is at %p\n", &key);
        while(1){
                sleep(1);
        }
}
