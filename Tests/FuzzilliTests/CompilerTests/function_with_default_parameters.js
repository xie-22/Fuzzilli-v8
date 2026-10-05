if (typeof output === 'undefined') output = console.log;

// plain function
function f(v1, v2=42) {
  return v1+v2;
}

output(f(42));
output(f(42,43));

// arrow function
const arrow = (v1, v2=10) => v1 + v2;
output(arrow(5));
output(arrow(5, 15));


// function expr
const expr = function(v1, v2="default") {
    return v1 + v2;
};
output(expr("hello "));
output(expr("hello ", "world"));


// generator function
function* gen(v1, v2=1) {
    yield v1;
    yield v2;
}
for (let v of gen(100)) {
    output(v);
}
for (let v of gen(100, 200)) {
    output(v);
}

// async function
async function asyncF(v1, v2=Promise.resolve(42)) {
    return v1 + await v2;
}
asyncF(10).then(output);
asyncF(10, Promise.resolve(20)).then(output);
