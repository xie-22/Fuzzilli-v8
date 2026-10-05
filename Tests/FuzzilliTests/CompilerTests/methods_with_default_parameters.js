if (typeof output === 'undefined') output = console.log;

// Object literal method
const propName = "computedMethod";
const obj = {
    method(v1, v2 = 42) {
        return v1 + v2;
    },
    [propName](v1, v2 = 10) {
        return v1 + v2;
    }
};

output(obj.method(5));
output(obj.method(5, 15));
output(obj.computedMethod(5));
output(obj.computedMethod(5, 15));

// Class constructor
class C {
    constructor(v1, v2 = "default") {
        this.v1 = v1;
        this.v2 = v2;
    }

    method(v1, v2 = 100) {
        return v1 + v2;
    }

    method_with_multiple_default_params_1(v1 = -1, v2 = 2, v3 = 3) {
        return -1 * v1 + v2 + v3;
    }

    method_with_multiple_default_params_2(v1, v2 = 2, v3 = 3) {
        return -1 * v1 + v2 + v3;
    }

    static staticMethod(v1, v2 = 200) {
        return v1 + v2;
    }

    [propName](v1, v2 = 300) {
        return v1 + v2;
    }

    ["computedMethodWithMultipleDefaultParams"](v1, v2 = 300, v3=400) {
        return -1 * v1 + v2 + v3;
    }
}

const instance = new C("hello");
output(instance.v1);
output(instance.v2);

output(instance.method(5));
output(instance.method(5, 15));

output(instance.method_with_multiple_default_params_1())
output(instance.method_with_multiple_default_params_1(10))
output(instance.method_with_multiple_default_params_2(10))
output(instance.method_with_multiple_default_params_2(-10, 20, 30))

output(instance.computedMethod(5));
output(instance.computedMethod(5, 15));

output(instance.computedMethodWithMultipleDefaultParams(-1));
output(instance.computedMethodWithMultipleDefaultParams(10, 2, 3));

const instance2 = new C("hello", "world");
output(instance2.v1);
output(instance2.v2);

output(C.staticMethod(10));
output(C.staticMethod(10, 20));
