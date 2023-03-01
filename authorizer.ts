import { decode, verify } from "jsonwebtoken";
import { JwksClient } from "jwks-rsa";

export class Authorizer {
  constructor(private jwksUri: string) {}

  public authorize(token: string): Promise<any> {
    console.log("** token **", token);
    const decoded = decode(token, { complete: true });
    console.log("** decoded **", decoded);
    const kid = decoded?.header?.kid;
    console.log("** kid **", kid);
    return this.getKey(kid!).then((x) => {
      console.log("** public key **", x);
      console.log("** verification result **", this.verify(token, x));
      return this.verify(token, x);
    });
  }

  private getKey(kid: string): Promise<string> {
    console.log(`**JWKS URI**: ${kid} - ${this.jwksUri}`);
    const client = new JwksClient({
      jwksUri: this.jwksUri,
    });

    return new Promise((resolve, reject) => {
      client.getSigningKey(kid, (err, key) => {
        console.log(`getSigningKey error: ${err}`);
        console.log("** key **", key);
        if (err) {
          reject(err);
        }
        resolve(key!.getPublicKey());
      });
    });
  }

  private verify(token: string, cert: string) {
    return new Promise((resolve, reject) => {
      verify(token, cert, {}, (err, decoded) => {
        if (err) {
          reject(err);
        }

        resolve(decoded);
      });
    });
  }
}
