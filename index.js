const express = require("express");
const multer = require("multer");
const app = express();
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

app.use(cors());

app.use(express.static("uploads"))

// Configuration de la base de données
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "db2023",
  database: "dietplus",
});

// Middleware pour vérifier le token JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, 'your_secret_key', (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
}

// Connexion à la base de données
connection.connect((err) => {
  if (err) {
    console.error("Erreur de connexion à la base de données :", err);
    return;
  }
  console.log("Connecté à la base de données MySQL");
});


const storage = multer.diskStorage({
  destination: function(req, file, cb){
    cb(null, "uploads/")
  },
  filename: function (req, file, cb) {
    const product = JSON.parse(req.body.product)
    const extension = file.originalname.split('.').pop();
    const pictureName = 'product_' + product.nom + '.' + extension; 
    req.image = pictureName;
    cb(null, pictureName)
  }
})
const upload = multer ({ storage: storage }).array("fichier")

// Configuration du middleware pour le parsing du corps de la requête
app.use(express.json());


// Route pour récupérer tous les product
app.get("/products", (req, res) => {
  connection.query("SELECT * FROM product", (err, results) => {
    if (err) {
      console.error("Erreur lors de la récupération des produits :", err);
      res.status(500).send("Erreur serveur");
      return;
    }
    res.json(results);
  });
});

// Route pour récupérer un product par son ID
app.get("/product/:id", (req, res) => {
  const productId = req.params.id;
  connection.query(
    "SELECT * FROM product WHERE id = ?",
    [productId],
    (err, results) => {
      if (err) {
        console.error("Erreur lors de la récupération de l'product :", err);
        res.status(500).send("Erreur serveur");
        return;
      }
      if (results.length === 0) {
        res.status(404).send("product non trouvé");
        return;
      }
      res.json(results[0]);
    }
  );
});

// Route pour créer un nouvel product
app.post("/product", upload, (req, res) => {
  const product = JSON.parse(req.body.product);
  if(req.image){
    product.image = req.image;
  }
  connection.query("INSERT INTO product SET ?", product, (err, result) => {
    if (err) {
      console.error("Erreur lors de la création de l'product :", err);
      res.status(500).send("Erreur serveur");
      return;
    }
    product.id = result.insertId;
    res.status(201).json(product);
  });
});

// Route pour mettre à jour un product
app.put("/product/:id", upload, (req, res) => {
  const productId = req.params.id;
  const product = JSON.parse(req.body.product);
  if(req.image){
    product.image = req.image;
  }
  connection.query(
    "UPDATE product SET ? WHERE id = ?",
    [product, productId],
    (err) => {
      if (err) {
        console.error("Erreur lors de la mise à jour de l'product :", err);
        res.status(500).send("Erreur serveur");
        return;
      }
      res.status(200).json(product);
    }
  );
});

// Route pour supprimer un product
app.delete("/product/:id", authenticateToken, (req, res) => {
  const productId = req.params.id;
  if(req.user.admin != 1){
    res.sendStatus(403)
    return;
  }
  connection.query("DELETE FROM product WHERE id = ?", [productId], (err) => {
    if (err) {
      console.error("Erreur lors de la suppression de l'product :", err);
      res.status(500).send("Erreur serveur");
      return;
    }
    res.sendStatus(204);
    return;
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Vérifier si l'utilisateur existe dans la base de données
  connection.query("SELECT * FROM user WHERE email = ?", [email], (err, results) => {
    if (err) {
      throw err;
    }

    if (results.length === 0) {
      return res.status(401).json({ message: "Adresse e-mail incorrecte" });
    }

    const user = results[0];

    // Vérifier le mot de passe
    bcrypt.compare(password, user.password, (bcryptErr, bcryptResult) => {
      if (bcryptErr || !bcryptResult) {
        return res.status(401).json({ message: "Mot de passe incorrect" });
      }

      // Générer un token JWT
      const token = jwt.sign(
        { email: user.email, admin: user.admin, nom: user.nom, prenom: user.prenom },
        "your_secret_key",
        { expiresIn: "1d" } // Expiration du token
      );

      // Retourner le token JWT
      res.json({ token });
    });
  });
});
// Point de terminaison pour l'inscription
app.post('/signup', upload, (req, res) => {

  console.log(req.body.user);
  const { email, password, admin, nom, prenom, image } = JSON.parse(req.body.user);

  // Vérifier si l'utilisateur existe déjà dans la base de données
  connection.query('SELECT * FROM user WHERE email = ?', [email], (err, results) => {
    if (err) {
      throw err;
    }

    if (results.length > 0) {
      return res.status(409).json({ message: 'Cet utilisateur existe déjà' });
    }

    // Hasher le mot de passe avant de l'enregistrer dans la base de données
    bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
      if (hashErr) {
        throw hashErr;
      }

      // Insérer le nouvel utilisateur dans la base de données
      connection.query('INSERT INTO user (email, password, admin, nom, prenom, image) VALUES (?, ?, ?, ?, ?, ?)', [email, hashedPassword, admin, nom, prenom, image], (insertErr, insertResult) => {
        if (insertErr) {
          throw insertErr;
        }

        // Générer un token JWT pour l'utilisateur nouvellement inscrit
        const token = jwt.sign(
          { email, admin, nom, prenom },
          'your_secret_key',
          { expiresIn: '1h' } // Expiration du token
        );

        // Retourner le token JWT
        res.json({ token });
      });
    });
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}.`);
});