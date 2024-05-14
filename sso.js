import CryptoJS from 'crypto-js'
import querystring from "qs";
import * as cheerio from 'cheerio';

export class SSO {
    constructor(account, password) {
        this.account = account
        this.password = password
        this.crypto_password = () => this.desEncrypt()
        this.cookies = {}
        this.flowkey = ''
        this.croypto = ''
        this.headers = () => {
            return {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Cookie': this.stringifyCookies()
            }
        }
    }

    async login() {
        try {
            await this._loginInit()
            const loginFormObj = {
                username: this.account,
                type: 'UsernamePassword',
                _eventId: 'submit',
                geolocation: '',
                execution: this.flowkey,
                captcha_code: '',
                croypto: this.croypto,
                password: this.crypto_password()
            }
            const loginReq = await fetch("https://sso.wuyiu.edu.cn/login", {
                "headers": {
                    ...this.headers(),
                    "content-type": "application/x-www-form-urlencoded",
                },
                "referrer": "https://sso.wuyiu.edu.cn/login?service=https://jwxt.wuyiu.edu.cn/",
                "body": querystring.stringify(loginFormObj),
                "method": "POST",
                redirect: "manual"
            });
            this.setThisCookie(loginReq.headers.getSetCookie() || [])
            const jsxsdTicketUrl = loginReq.headers.get('location')
            const jsxsdTicketReq = await fetch(jsxsdTicketUrl, {
                "headers": {
                    ...this.headers(),
                },
                "referrer": "https://sso.wuyiu.edu.cn/login?service=https://jwxt.wuyiu.edu.cn/",
                "method": "GET",
                redirect: "manual"
            });
            if(jsxsdTicketReq.status === 302 && jsxsdTicketReq.headers.get('location') === 'https://jwxt.wuyiu.edu.cn/jsxsd/') {
                this.setThisCookie(jsxsdTicketReq.headers.getSetCookie() || [])
                console.log('登录成功！')
                return
            }
            throw new Error('登录失败☹️')
        } catch (e) {
            console.log('login -- 错误 ',e)
        }
    }
    async _loginInit() {
        try {
            const initReq = await fetch("https://sso.wuyiu.edu.cn/login?service=https://jwxt.wuyiu.edu.cn/jsxsd/", {
                "headers": {
                    ...this.headers(),
                },
                "method": "GET",
            });
            const initRes = await initReq.text()
            const flowkeyRegex = /<p id="login-page-flowkey">([^<]+)<\/p>/g;
            const croyptoRegex = /<p id="login-croypto">([^<]+)<\/p>/g;
            this.flowkey = flowkeyRegex.exec(initRes)[1]
            this.croypto = croyptoRegex.exec(initRes)[1]
            this.setThisCookie(initReq.headers.getSetCookie() || [])
        } catch (e) {
            console.log('_loginInit -- 错误',e)
        }
    }
    async getUser() {
        try {

            const userReq = await fetch("https://jwxt.wuyiu.edu.cn/jsxsd/grxx/xsxx", {
                "headers": {
                    ...this.headers()
                },
                "method": "GET",
            });
            const userReq2 = await fetch("https://jwxt.wuyiu.edu.cn/jsxsd/grxx/xsxx", {
                "headers": {
                    ...this.headers()
                },
                "method": "GET",
            });
            const userRes = await userReq2.text()
            const user = this.parseHtmlString(userRes)
            console.log(`你好👋，${user['姓名']}`)
            return user
        } catch (e) {
            console.log('getUser 错误 -- ', e)
        }
    }
    parseHtmlString(htmlString) {
        const $ = cheerio.load(htmlString);
        const labelElements = $('label');
        const result = {};
        labelElements.each(function() {
            const name = $(this).text().trim();
            if (name) {
                const input = $(this).next().find('input');
                if (input.length > 0) {
                    const value = input.attr('value');
                    if (value) {
                        result[name] = "";
                    }
                    result[name] = value
                }
            }
        });

        return result;
    }
    setThisCookie(setCookieArray) {
        setCookieArray.forEach(cookieString => {
            const matches = cookieString.match(/([^=]+)=([^;]+)/);
            if (matches) {
                const cookieName = String(matches[1]);
                this.cookies[cookieName] = String(matches[2]);
            }
        });
    }
    desEncrypt() {
        const n = CryptoJS.enc.Base64.parse(this.croypto)
        return CryptoJS.DES.encrypt(this.password, n, {
            mode: CryptoJS.mode.ECB,
            padding: CryptoJS.pad.Pkcs7
        }).toString()
    }
    stringifyCookies() {
        return querystring.stringify(this.cookies).replace(/&/g, '; ')
    }
    generateCsrfToken() {
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const charactersLength = characters.length;
        let randomString = "";

        for (let i = 0; i < 32; i++) {
            randomString += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        const csrfKey = randomString
        const encodedKey = btoa(csrfKey);
        const csrfValue = encodedKey.substring(0, encodedKey.length / 2) + encodedKey + encodedKey.substring(encodedKey.length / 2);
        const hashedValue = CryptoJS.MD5(csrfValue).toString();
        return { csrfKey, csrfValue: hashedValue };
    }
}
