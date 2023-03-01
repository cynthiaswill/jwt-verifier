import { Authorizer } from "./authorizer";

const uri =
  "https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_8KXI60lj6/.well-known/jwks.json";
const client = new Authorizer(uri);

const token: string =
  "eyJraWQiOiIwaDR1VVV0MTJ6SlhVRk00am5JKzI5NmR0djk3ZFwvdjdvdGNUNDBna0wzbz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJiMWY2ZDI3MS00NDNhLTQwNzctYTcyNC1lYzlkYzlmMzcxMGEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLmV1LXdlc3QtMi5hbWF6b25hd3MuY29tXC9ldS13ZXN0LTJfOEtYSTYwbGo2IiwiY3VzdG9tOmdyb3VwIjoiQURNSU58QWRtaW5pc3RyYXRvciIsImNvZ25pdG86dXNlcm5hbWUiOiJ5aS56aGFuZyIsIm9yaWdpbl9qdGkiOiJjNzFhZmFlZC04MjFkLTQ4YmMtYjY4OS1hZmFkMzBlZDZmYjkiLCJjdXN0b206dGVuYW50SWQiOiJEZWx0YUNhcGl0YTJ8RGVsdGFDYXBpdGExfERldXRzY2hlQmFuayIsImF1ZCI6Ijc3MzRuNnExOWc4N2F0M3FhODI4aW90bGkyIiwiZXZlbnRfaWQiOiJjYWNjOTczMC1hMDBkLTRjMGQtYTY0MS1iMDZkNzZiZTY0NzciLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY3NzU4NTg3MiwiZXhwIjoxNjc3NjU2NDUwLCJpYXQiOjE2Nzc2NTI4NTAsImp0aSI6Ijg2YTJiYjkyLThhMDAtNDBiMS04ZDZmLTk3NGM2N2I2OWU2YyIsImVtYWlsIjoieWkuemhhbmdAZGVsdGFjYXBpdGEuY29tIn0.tVq6jbSLLUajtTWUPSOWoxykw_CdP68pASnctIvHovyjLpeyauTMysVaVREskA8Fl2SImJTmuA2PBTq3wHdTliGu5Z9x7VnVjBuJYJ-fFPUFJymaeJgWKfknOB_4nCTH709MVrylPi_QpUFmZX72YjyaakJ_TLFG92xXd67k8h9yvHE4PypIGwY3sMggOVZlKkqpEOIJa1Pu130-vdUW7MK3_y_F7WSxT3X5HMitfXk-j-cGCD9lbz7UAaOOp-gxeHmLaxsSojwLBPWTpS9xtvPuB1uNsqtJF7jRkB6Znu4rkcuXQqxne55cwccbwfYlcu8XDIZ6Pvu50e5-KGZAWQ";

async function verify(token: string) {
  await client.authorize(token);
}

verify(token);