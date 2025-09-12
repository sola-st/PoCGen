Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object
prototypes, which may then be inherited by user-defined objects.
User-controllable objects are often derived from a JSON string using the `JSON.parse()` method.
Interestingly, `JSON.parse()` also treats any key in the JSON object as an arbitrary string, including things like
`__proto__`.
This provides another potential vector for prototype pollution.
Let's say an attacker injects the following malicious JSON, for example, via a web message:

```json
{
  "__proto__": {
    "exploited": true
  }
}
```

If this is converted into a JavaScript object via the `JSON.parse()` method, the resulting object will in fact have a
property with the key __proto__:

```js
const objectLiteral = {__proto__: {evilProperty: 'payload'}};
const objectFromJson = JSON.parse('{"__proto__": {"evilProperty": "payload"}}');
objectLiteral.hasOwnProperty('__proto__');     // false
objectFromJson.hasOwnProperty('__proto__');     // true
```

If the object created via JSON.parse() is subsequently merged into an existing object without proper key sanitization,
this will also lead to prototype pollution during the assignment.
A common pitfall in trying to prevent prototype pollution is to check for
`key === "__proto__" || key === "constructor" || key === "prototype"`.
This is not sufficient, as the attacker can create an array `["__proto__"]` to bypass it.
