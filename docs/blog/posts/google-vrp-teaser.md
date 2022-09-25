---
description: On August 9, the @GoogleVRP Twitter account as well as multiple Googlers started teasing an event with a link to a login page as well as a video. This small post exlains how to get the password and what it reveals.
authors:
  - techbrunch
date: 2022-09-25
---

# Google VRP Teaser

## Introduction

On August 9, the @GoogleVRP Twitter account as well as multiple Googlers started teasing an event with a link to a login page as well as a video. This small blogpost exlains how to get the password and what it reveals.

<!-- more -->

![Google VRP Teaser](google-vrp-teaser/Tweet%20by%20Google%20VRP%20(Google%20Bug%20Hunters)-2.png)

The tweet talks about a countdown and the video description and content mention:

> Hope is not a strategy. [GOO.GLE/H4CK1NGG00GL3](GOO.GLE/H4CK1NGG00GL3)

<iframe width="560" height="315" src="https://www.youtube.com/embed/YfBqflOySB8" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

Hope is not a strategy or "Spes consilium non" in Latin is a saying from the SRE team at Google:

!!! quote
    An oft-heard SRE saying is that you should “design a system to be as available as is required, but not much more.” At Google, when designing a system, we generally target a given availability figure (e.g., 99.9%), rather than particular MTBF or MTTR figures. Once we’ve achieved that availability metric, we optimize our operations for "fast fix," e.g., MTTR over MTBF, accepting that **failure is inevitable, and that “spes consilium non est” (Hope is not a strategy)**. SREs are often able to mitigate the user visible impact of huge problems in minutes, allowing our engineering teams to achieve high development velocity, while simultaneously earning Google a reputation for great availability.

This saying is even on the Google CRE team patch:

![](google-vrp-teaser/Tweet%20by%20Liz%20Fong-Jones%20(%E6%96%B9%E7%A6%AE%E7%9C%9F)-2.png)

## Reversing Firebase 

The link redirects to an [appspot website](https://gweb-h4ck1ng-g00gl3.uc.r.appspot.com/) displaying a login form:

![Enter password](google-vrp-teaser/enter-password.png)

The application is a SPA using Angular & [Firebase with a Realtime Database](https://firebase.google.com/docs/database).

!!! warning
    Since the Firebase application is using a Realtime Database you should look into WebSockets communication when analyzing the traffic.

There is a simple password form which redirects to a google search if the password is not the expected one.

Since this is a single page application let's look at the minified JavaScript code:

```javascript
class n {
    constructor(e, s) {
        this.authService = e,
        this.storage = s,
        this.authenticated = !1,
        this.transitioning = !1,
        this.showCountdown = !1,
        this.title = "Teaser Home Page",
        this.authFailRedirect = "https://google.com/search?q=",
        !0 === this.storage.retrieve("teaser.authenticated") && (this.authenticated = !0,
        this.showCountdown = !0)
    }
    authenticate(e) {
        var s = this;
        return (0,
        W.Z)(function*() {
            if (s.authenticated)
                return;
            setTimeout(()=>{
                s.startTransition()
            }
            , 100);
            const a = yield s.authService.checkPassword(e);
            s.authenticated = a,
            a ? (s.storage.store("teaser.authenticated", !0),
            window.gtag("event", "page_view", {
                event_action: "submit",
                event_label: "teaser_unlock",
                page_location: window.location.href,
                page_path: "/unlock"
            })) : window.location.href = `${s.authFailRedirect}${e}`
        })()
    }
    // ...
}
```

The code used to check the password 

```javascript
ET = (() => {  
    class n {  
        constructor(e) {  
            this.database = e  
        }  
        s(e) {  
            var s = this;  
            return (0, W.Z)(function*() {  
                const a = s.database.list("flags/teaser", _ => _.orderByValue().equalTo(e?.toLowerCase())).valueChanges();  
                return (yield function ae(n, t) {  
                    const e = "object" == typeof t;  
                    return new Promise((s, a) => {  
                        const h = new ee.Hp({  
                            next: _ => {  
                                s(_), h.unsubscribe()  
                            },  
                            error: a,  
                            complete: () => {  
                                e ? s(t.defaultValue) : a(new Sd)  
                            }  
                        });  
                        n.subscribe(h)  
                    })  
                }(a))?.length > 0  
            })()  
        }  
    }  
    return n.\u0275fac = function(e) {  
        return new(e || n)(m.LFG(yS))  
    }, n.\u0275prov = m.Yz7({  
        token: n,  
        factory: n.\u0275fac,  
        providedIn: "root"  
    }), n  
})();
```

If the data retrieved from the database is `> 0` then `authenticated` will be `true` and this will only happen if the password that we send is the one stored in the database.

To retrieve the password we first need the Firebase configuration which can be found in the JavaScript code:


```js
const IT_firebase = {  
    apiKey: "AIzaSyBSeXZQjiyPUBkQDj-FUubN05bt50PzsgI",  
    authDomain: "gweb-h4ck1ng-g00gl3.firebaseapp.com",  
    projectId: "gweb-h4ck1ng-g00gl3",  
    storageBucket: "gweb-h4ck1ng-g00gl3.appspot.com",  
    messagingSenderId: "267897667426",  
    appId: "1:267897667426:web:d839498d3f03a9957a363b"  
};
```

Here is the code I used to get the FLAG:

```javascript
import { initializeApp } from "firebase/app";
import { getDatabase, ref, onValue} from "firebase/database";

// See: https://firebase.google.com/docs/web/learn-more#config-object
const firebaseConfig = {
    apiKey: "AIzaSyBSeXZQjiyPUBkQDj-FUubN05bt50PzsgI",
    authDomain: "gweb-h4ck1ng-g00gl3.firebaseapp.com",
    projectId: "gweb-h4ck1ng-g00gl3",
    storageBucket: "gweb-h4ck1ng-g00gl3.appspot.com",
    messagingSenderId: "267897667426",
    appId: "1:267897667426:web:d839498d3f03a9957a363b"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const db = getDatabase(app);

console.log(db);

// https://firebase.google.com/docs/database/web/read-and-write#read_data_once
const test = ref(db, 'flags');
onValue(test, (snapshot) => {
    const data = snapshot.val();
    console.log(data); // { teaser: { name: 'operationaurora' } }
});
```

!!! info
    The flag `operationaurora` maybe refers to [Operation Aurora](https://en.wikipedia.org/wiki/Operation_Aurora) a series of cyber attacks conducted by advanced persistent threats such as the Elderwood Group based in Beijing, China, with ties to the People's Liberation Army. First publicly disclosed by Google on January 12, 2010.

Once entered a countdown is displayed ending the GMT: Friday 30 September 2022 22:00:00.

![Countdown](google-vrp-teaser/countdown.png)

Any ideas what is going to happen in 5 days ?