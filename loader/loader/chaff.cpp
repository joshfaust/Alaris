#include <string>
#include <iostream>
#include <Windows.h>
#include <string>
#include <stdio.h>
#include "chaff.h"

using namespace std;

int chaff::fib()
{
    int n, t1 = 0, t2 = 1, nextTerm = 0;
    n = 12094584;

    for (int i = 1; i <= n; ++i) {
        // Prints the first two terms.
        if (i == 1) {
            continue;
        }
        if (i == 2) {
            continue;
        }
        nextTerm = t1 + t2;
        t1 = t2;
        t2 = nextTerm;
    }
    return 0;
}

int chaff::prime()
{
    bool isPrime;
    for (int n = 2; n < 10000; n++) {
        isPrime = isPrimeNumber(n);

        if (isPrime == true)
            int a = 1;
    }
    return 0;
}

int chaff::isPrimeNumber(int n) {
    bool isPrime = true;

    for (int i = 2; i <= n / 2; i++) {
        if (n % i == 0) {
            isPrime = false;
            break;
        }
    }
    return isPrime;
}