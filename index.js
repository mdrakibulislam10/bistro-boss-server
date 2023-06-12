const express = require("express");
const app = express();
const cors = require("cors");
require('dotenv').config();
const jwt = require('jsonwebtoken');
const stripe = require("stripe")(process.env.PAYMENT_SECRET_KEY);
const port = process.env.PORT || 5000;

// middleware
app.use(cors());
app.use(express.json());

// verify jwt token;
const verifyJwt = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: "unauthorized access" });
    }

    // bearer token
    const token = authorization.split(" ")[1];
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ error: true, message: "unauthorized access" });
        }

        req.decoded = decoded;
        next();
    });
};

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.pqpiudt.mongodb.net/?retryWrites=true&w=majority`;
// console.log(uri);

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        client.connect();

        // collections
        const usersCollection = client.db("bistroDB").collection("users");
        const menuCollection = client.db("bistroDB").collection("menu");
        const reviewsCollection = client.db("bistroDB").collection("reviews");
        const cartCollection = client.db("bistroDB").collection("carts");
        const paymentCollection = client.db("bistroDB").collection("payments");

        // jwt
        app.post("/jwt", (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1h" });
            // console.log({ token }); // make obj prop token: token,
            res.send({ token });
        });

        // warning: use verifyJwt() before using verifyAdmin();
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email; // decoded from verifyJwt();
            const query = { email: email };
            const user = await usersCollection.findOne(query);

            if (user?.role !== "admin") {
                return res.status(403).send({ error: true, message: "forbidden message" });
            }

            next(); // if user?.role === "admin";
        };

        /* 
        0. do not show secure links to those who should not see links
        1. use jwt token: verifyJwt
        2. use verifyAdmin middleWare
        */

        // users related apis
        app.get("/users", verifyJwt, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        });

        app.post("/users", async (req, res) => {
            const user = req.body;
            // console.log(user);
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);
            console.log(existingUser);
            if (existingUser) {
                // res.send({ message: "user already exists" });
                return res.send({ message: "user already exists" });
            }
            // else{
            const result = await usersCollection.insertOne(user);
            res.send(result);
            // }
        });

        // security layer: verifyJwt
        // email same
        // check admin
        app.get("/users/admin/:email", verifyJwt, async (req, res) => {
            const email = req.params.email;

            if (req.decoded.email !== email) { // login email !== route e pathano email;
                return res.send({ admin: false });
            };

            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === "admin" }; // admin: true or false;
            res.send(result);
        });

        app.patch("/users/admin/:id", async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    role: "admin",
                },
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // menu related apis
        app.get("/menu", async (req, res) => {
            const result = await menuCollection.find().toArray();
            res.send(result);
        });

        app.post("/menu", verifyJwt, verifyAdmin, async (req, res) => {
            const newItem = req.body;
            const result = await menuCollection.insertOne(newItem);
            res.send(result);
        });

        app.delete("/menu/:id", verifyJwt, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) }
            const result = await menuCollection.deleteOne(query);
            res.send(result);
        });

        // reviews related apis
        app.get("/reviews", async (req, res) => {
            const result = await reviewsCollection.find().toArray();
            res.send(result);
        });

        // cart collection apis;
        app.get("/carts", verifyJwt, async (req, res) => {
            const email = req.query.email;
            if (!email) {
                res.send([]);
            }

            // jwt email verify
            if (email !== req.decoded.email) {
                return res.status(401).send({ error: true, message: "forbidden access" });
            }

            else {
                const query = { email: email };
                const result = await cartCollection.find(query).toArray();
                res.send(result);
            }
        });

        app.post("/carts", async (req, res) => {
            const item = req.body;
            // console.log(req.body);
            const result = await cartCollection.insertOne(item);
            res.send(result);
        });

        app.delete("/carts/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await cartCollection.deleteOne(query);
            res.send(result);
        });

        // create payment intent
        app.post("/create-payment-intent", verifyJwt, async (req, res) => {
            const { price } = req.body; // destructuring kore neya hocche;
            const amount = parseInt(price * 100); // convert tk to cents(poisa); stripe poisa hisebe dhore tai 100 diye gun kore poisa baniye pathacchi; 1 tk(any) = 100 poisa / cents;

            // console.log(price, amount);

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: "usd",
                payment_method_types: ["card"],
            });
            res.send(
                {
                    clientSecret: paymentIntent.client_secret,
                }
            )
        });

        // payment related api;
        app.post("/payments", verifyJwt, async (req, res) => {
            const payment = req.body;
            // payment.menuItems = payment.menuItems.map(id => new ObjectId(id)); // for aggregate;

            const insertResult = await paymentCollection.insertOne(payment);

            const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } }; // data(body data) er moddhe kono arr thakle sei arr er upore kono operation jemon, map, etc, korte hole $in use korbo.
            const deleteResult = await cartCollection.deleteMany(query);

            res.send({ insertResult, deleteResult });
        });

        app.get("/admin-stats", verifyJwt, verifyAdmin, async (req, res) => {
            const users = await usersCollection.estimatedDocumentCount(); // length of collection;
            const products = await menuCollection.estimatedDocumentCount();
            const orders = await paymentCollection.estimatedDocumentCount();

            // best way to get sum of the price field is to use group and sum operator;
            /* await paymentCollection.aggregate([
                    {
                        $group: {
                            _id: null, // Group all documents together // sobgulo data ke nibe kono specific data na arki;
                            totalPrice: {
                                $sum: "$price" // Calculate the sum of the "price" field
                            }
                        }
                    }
                ]); */

            const payments = await paymentCollection.find().toArray(); // all paymentsCollections data get;
            const revenue = payments.reduce((sum, payment) => sum + payment.price, 0);

            res.send({
                revenue,
                users,
                products,
                orders,
            })
        });

        /* 
        Bangla system(2nd best system):
        1. load all payments data: find() all from paymentsCollection;
        2. for each payment, get the menuItems array: data er moddh thaka menuItems arr ta nibo;
        3. for each item in the menuItems array get the menuItem form the menu collection: menuItems e thaka id diye menu collection e thaka data gulo find() korbo;
        4. put them an array: allOrderedItems - etodin dhore joto order place kora hoyeche segulo;
        5. separate(alada) allOrderedItems by category using filter:
        6. Now get the quantity by using length: pizzas.length;
        7. for each category use reduce to get the total amount spend on this category:
        */

        app.get("/order-stats", verifyJwt, verifyAdmin, async (req, res) => {
            const pipeline = [
                {
                    $lookup: {
                        from: 'menu',
                        localField: 'menuItems',
                        foreignField: '_id',
                        as: 'menuItemsData'
                    }
                },
                {
                    $unwind: '$menuItemsData'
                },
                {
                    $group: {
                        _id: '$menuItemsData.category',
                        count: { $sum: 1 },
                        total: { $sum: '$menuItemsData.price' }
                    }
                },
                {
                    $project: {
                        category: '$_id',
                        count: 1,
                        total: { $round: ['$total', 2] },
                        _id: 0
                    }
                }
            ];

            const result = await paymentCollection.aggregate(pipeline).toArray();
            // res.send(result);

            const demoArr = [
                { count: 3, category: "pizza", total: 45.5 },
                { count: 2, category: "drinks", total: 35.3 },
                { count: 2, category: "pizza", total: 56.5 },
            ];
            res.send(demoArr);
        });

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get("/", (req, res) => {
    res.send("boos is sitting");
});

app.listen(port, () => {
    console.log(`Bistro boss is sitting on port: ${port}`);
});

/* 
# Naming convention:
...................
* users : userCollection - collection name example;
* app.get("/users") - all data get;
* app.get("/users/:id") - single data get;
* app.post("/users") - post data;
* app.patch("/users/:id") - data up with patch;
* app.put("/users/:id") - data up with put;
* app.delete("/users/:id") - delete single data;
*/