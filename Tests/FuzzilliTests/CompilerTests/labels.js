L1: {
    L2: {
        console.log("a");
        {
            console.log("b")
        }
        L3: {
            console.log("c");
            break L1;
            break L2;
        }
        console.log("d");
        break L1;
    }
    console.log("e");
    break L1;
}

L4: {
    L5: {
        L6: {
            console.log("0");
            L7: {
                break L5;
            }
            console.log("1");
            break L4;
        }
    }
}

F1: for (let i = 0; i < 10; i++) {
    F2: for (let j = 0; j < 10; j++) {
        if (j == 5) continue F1;
        if (i == 1) break F1;
    }
}

W1: while (true) {
    W2: while(true) {
        break W1;
        continue W2;
    }
}

D1: do {
    D2: do {
        break D1;
        continue D2;
    } while (true);
} while (true);

FI1: for (let x in {a: 1}) {
    FI2: for (let y in {a: 1}) {
        break FI1;
        continue FI2;
    }
}

FO1: for (let x of [1, 2]) {
    FO2: for (let y of [1, 2]) {
        break FO1;
        continue FO2;
    }
}

S1: switch (true) {
        case true:
            S2: switch (true) {
                case true:
                    break S1;
                    break S2;
            }
}

I1: if (true) {
    I2: if (true) {
        break I1;
        break I2;
    } else {
        break I1;
        break I2;
    }
} else {
    I3: if (true) {
        break I1;
    } else {
        break I3;
    }
}
