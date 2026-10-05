if (typeof output === 'undefined') output = console.log;

const a = [1, 2, 3];
output(delete a[9223372036854775808]);
output(a);
