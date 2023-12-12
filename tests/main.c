#include <stdio.h>

int add(int a, int b)
{
	return a + b;
}

int main(int a, int b)
{
	int sum = 0;
	while(1){
		sum = add(a, b);
	}
	printf("sum1: %d\n", sum);
	return sum;
}
