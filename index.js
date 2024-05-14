import {SSO} from "./sso.js";

const sso = new SSO('账号', '密码')
await sso.login()
await sso.getUser()
console.log(sso.cookies)
