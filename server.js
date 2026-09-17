require("dotenv").config();

const express = require("express");
const PDFDocument = require("pdfkit");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const nodemailer = require("nodemailer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;


// =========================================================
// CONFIGURACIÓN DE UPLOADS - GALERÍA
// =========================================================

const uploadsDir = path.join(__dirname, "public", "uploads");

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({

  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },

  filename: (req, file, cb) => {

    const ext = path.extname(file.originalname).toLowerCase();

    const safeName =
      Date.now() +
      "-" +
      crypto.randomBytes(8).toString("hex") +
      ext;

    cb(null, safeName);
  }

});


const upload = multer({

  storage,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {

    const allowed = [
      "image/jpeg",
      "image/png",
      "image/webp",
      "image/gif"
    ];

    if (!allowed.includes(file.mimetype)) {

      return cb(
        new Error(
          "Solo se permiten imágenes JPG, PNG, WEBP o GIF."
        )
      );

    }

    cb(null, true);
  }

});


// =========================================================
// MYSQL
// =========================================================

const pool = mysql.createPool({

  host: process.env.DB_HOST,

  port: Number(
    process.env.DB_PORT || 3306
  ),

  user: process.env.DB_USER,

  password: process.env.DB_PASSWORD,

  database: process.env.DB_NAME,

  waitForConnections: true,

  connectionLimit: 10,

  charset: "utf8mb4"

});


// =========================================================
// MIDDLEWARE
// =========================================================

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.urlencoded({
    extended: false
  })
);

app.use(express.json());

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


// =========================================================
// SESIONES
// =========================================================

app.use(
  session({

    secret: process.env.SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    store: new MySQLStore({}, pool),

    cookie: {

      httpOnly: true,

      sameSite: "lax",

      secure:
        process.env.NODE_ENV === "production",

      maxAge:
        1000 * 60 * 60 * 8

    }

  })
);


// =========================================================
// RATE LIMIT
// =========================================================

const authLimiter = rateLimit({

  windowMs:
    15 * 60 * 1000,

  limit: 20,

  standardHeaders: true,

  legacyHeaders: false

});


// =========================================================
// AUTENTICACIÓN
// =========================================================

function requireAuth(req, res, next) {

  if (!req.session.user) {

    return res.status(401).json({
      error: "Debes iniciar sesión."
    });

  }

  next();
}


function requireAdmin(req, res, next) {

  if (
    !req.session.user ||
    req.session.user.role !== "admin"
  ) {

    return res.status(403).json({
      error:
        "Acceso exclusivo para administradores."
    });

  }

  next();
}


function cleanUser(user) {

  return {

    id: user.id,

    name: user.name,

    email: user.email,

    role: user.role

  };

}


// =========================================================
// EMAIL DE RECUPERACIÓN
// =========================================================

async function sendResetEmail(
  email,
  token
) {

  const transporter =
    nodemailer.createTransport({

      host: process.env.SMTP_HOST,

      port: Number(
        process.env.SMTP_PORT || 465
      ),

      secure:
        String(
          process.env.SMTP_SECURE
        ).toLowerCase() === "true",

      auth: {

        user:
          process.env.SMTP_USER,

        pass:
          process.env.SMTP_PASSWORD

      }

    });


  const link =
    `${process.env.APP_URL}/reset-password.html?token=${encodeURIComponent(token)}`;


  await transporter.sendMail({

    from:
      process.env.MAIL_FROM,

    to:
      email,

    subject:
      "Recuperación de contraseña - JR Electricidad",

    html: `

      <div style="font-family:Arial,sans-serif;line-height:1.6">

        <h2>
          JR Electricidad ⚡
        </h2>

        <p>
          Recibimos una solicitud para cambiar tu contraseña.
        </p>

        <p>
          <a href="${link}">
            Restablecer contraseña
          </a>
        </p>

        <p>
          Este enlace vence en 30 minutos.
        </p>

        <p>
          Si no solicitaste este cambio,
          puedes ignorar este correo.
        </p>

      </div>

    `

  });

}


// =========================================================
// CUENTA DEL USUARIO - CONTRASEÑA
// =========================================================

app.put(
  "/api/account/password",
  requireAuth,
  authLimiter,
  async (req, res) => {

    try {

      const currentPassword =
        String(
          req.body.currentPassword || ""
        );

      const newPassword =
        String(
          req.body.newPassword || ""
        );


      if (
        !currentPassword ||
        !newPassword
      ) {

        return res.status(400).json({
          error:
            "Completa todos los campos."
        });

      }


      if (newPassword.length < 8) {

        return res.status(400).json({
          error:
            "La nueva contraseña debe tener al menos 8 caracteres."
        });

      }


      if (
        currentPassword ===
        newPassword
      ) {

        return res.status(400).json({
          error:
            "La nueva contraseña debe ser diferente a la actual."
        });

      }


      const [rows] =
        await pool.query(
          `
          SELECT
            id,
            password_hash
          FROM users
          WHERE id=?
          LIMIT 1
          `,
          [
            req.session.user.id
          ]
        );


      if (!rows.length) {

        return res.status(404).json({
          error:
            "Usuario no encontrado."
        });

      }


      const validPassword =
        await bcrypt.compare(
          currentPassword,
          rows[0].password_hash
        );


      if (!validPassword) {

        return res.status(401).json({
          error:
            "La contraseña actual es incorrecta."
        });

      }


      const hash =
        await bcrypt.hash(
          newPassword,
          12
        );


      await pool.query(
        `
        UPDATE users
        SET password_hash=?
        WHERE id=?
        `,
        [
          hash,
          req.session.user.id
        ]
      );


      const user =
        {
          ...req.session.user
        };


      await new Promise(
        (resolve, reject) => {

          req.session.regenerate(
            (err) => {

              if (err) {
                return reject(err);
              }

              resolve();

            }
          );

        }
      );


      req.session.user = user;


      await new Promise(
        (resolve, reject) => {

          req.session.save(
            (err) => {

              if (err) {
                return reject(err);
              }

              resolve();

            }
          );

        }
      );


      await pool.query(
        `
        DELETE FROM sessions
        WHERE session_id <> ?
        `,
        [
          req.sessionID
        ]
      );


      res.json({

        ok: true,

        message:
          "Contraseña actualizada. Las demás sesiones fueron cerradas."

      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo cambiar la contraseña."

      });

    }

  }
);


// =========================================================
// CUENTA DEL USUARIO - EMAIL
// =========================================================

app.put(
  "/api/account/email",
  requireAuth,
  authLimiter,
  async (req, res) => {

    try {

      const newEmail =
        String(
          req.body.newEmail || ""
        )
        .trim()
        .toLowerCase();


      const currentPassword =
        String(
          req.body.currentPassword || ""
        );


      if (
        !newEmail ||
        !currentPassword
      ) {

        return res.status(400).json({
          error:
            "Completa todos los campos."
        });

      }


      const emailRegex =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


      if (!emailRegex.test(newEmail)) {

        return res.status(400).json({
          error:
            "Ingresá un correo electrónico válido."
        });

      }


      if (
        newEmail ===
        req.session.user.email
      ) {

        return res.status(400).json({
          error:
            "El nuevo correo es igual al actual."
        });

      }


      const [existing] =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email=?
          AND id<>?
          LIMIT 1
          `,
          [
            newEmail,
            req.session.user.id
          ]
        );


      if (existing.length) {

        return res.status(409).json({
          error:
            "Ese correo ya está registrado."
        });

      }


      const [rows] =
        await pool.query(
          `
          SELECT
            id,
            password_hash
          FROM users
          WHERE id=?
          LIMIT 1
          `,
          [
            req.session.user.id
          ]
        );


      if (!rows.length) {

        return res.status(404).json({
          error:
            "Usuario no encontrado."
        });

      }


      const validPassword =
        await bcrypt.compare(
          currentPassword,
          rows[0].password_hash
        );


      if (!validPassword) {

        return res.status(401).json({
          error:
            "La contraseña actual es incorrecta."
        });

      }


      await pool.query(
        `
        UPDATE users
        SET email=?
        WHERE id=?
        `,
        [
          newEmail,
          req.session.user.id
        ]
      );


      req.session.user.email =
        newEmail;


      res.json({

        ok: true,

        message:
          "Correo electrónico actualizado correctamente.",

        user:
          cleanUser(
            req.session.user
          )

      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo cambiar el correo electrónico."

      });

    }

  }
);


// =========================================================
// USUARIO ACTUAL
// =========================================================

app.get(
  "/api/me",
  (req, res) => {

    res.json({

      user:
        req.session.user
          ? cleanUser(
              req.session.user
            )
          : null

    });

  }
);


// =========================================================
// REGISTRO
// =========================================================

app.post(
  "/api/register",
  authLimiter,
  async (req, res) => {

    try {

      const {
        name,
        email,
        password
      } = req.body;


      if (
        !name ||
        !email ||
        !password
      ) {

        return res.status(400).json({
          error:
            "Completa todos los campos."
        });

      }


      if (password.length < 8) {

        return res.status(400).json({
          error:
            "La contraseña debe tener al menos 8 caracteres."
        });

      }


      const normalized =
        email
          .trim()
          .toLowerCase();


      const [exists] =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email=?
          `,
          [
            normalized
          ]
        );


      if (exists.length) {

        return res.status(409).json({
          error:
            "Ese correo ya está registrado."
        });

      }


      const hash =
        await bcrypt.hash(
          password,
          12
        );


      const [result] =
        await pool.query(
          `
          INSERT INTO users
          (name,email,password_hash)
          VALUES (?,?,?)
          `,
          [
            name.trim(),
            normalized,
            hash
          ]
        );


      req.session.user = {

        id:
          result.insertId,

        name:
          name.trim(),

        email:
          normalized,

        role:
          "user"

      };


      res.json({

        ok: true,

        user:
          cleanUser(
            req.session.user
          )

      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo crear la cuenta."

      });

    }

  }
);


// =========================================================
// LOGIN
// =========================================================

app.post(
  "/api/login",
  authLimiter,
  async (req, res) => {

    try {

      const email =
        (
          req.body.email || ""
        )
        .trim()
        .toLowerCase();


      const password =
        req.body.password || "";


      const [rows] =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE email=?
          `,
          [
            email
          ]
        );


      if (
        !rows.length ||
        !(
          await bcrypt.compare(
            password,
            rows[0].password_hash
          )
        )
      ) {

        return res.status(401).json({
          error:
            "Correo o contraseña incorrectos."
        });

      }


      req.session.user =
        cleanUser(
          rows[0]
        );


      res.json({

        ok: true,

        user:
          req.session.user

      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo iniciar sesión."

      });

    }

  }
);


// =========================================================
// LOGOUT
// =========================================================

app.post(
  "/api/logout",
  (req, res) => {

    req.session.destroy(
      () => {

        res.json({
          ok: true
        });

      }
    );

  }
);


// =========================================================
// RECUPERAR CONTRASEÑA
// =========================================================

app.post(
  "/api/forgot-password",
  authLimiter,
  async (req, res) => {

    try {

      const email =
        (
          req.body.email || ""
        )
        .trim()
        .toLowerCase();


      const [rows] =
        await pool.query(
          `
          SELECT
            id,
            email
          FROM users
          WHERE email=?
          `,
          [
            email
          ]
        );


      if (rows.length) {

        const token =
          crypto.randomBytes(32)
            .toString("hex");


        const tokenHash =
          crypto.createHash(
            "sha256"
          )
          .update(token)
          .digest("hex");


        await pool.query(
          `
          INSERT INTO password_resets
          (
            user_id,
            token_hash,
            expires_at
          )
          VALUES
          (
            ?,
            ?,
            DATE_ADD(
              NOW(),
              INTERVAL 30 MINUTE
            )
          )
          `,
          [
            rows[0].id,
            tokenHash
          ]
        );


        try {

          await sendResetEmail(
            rows[0].email,
            token
          );

        } catch (mailError) {

          console.error(
            "SMTP:",
            mailError.message
          );

        }

      }


      res.json({

        ok: true,

        message:
          "Si el correo está registrado, recibirás instrucciones para recuperar tu contraseña."

      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo procesar la solicitud."

      });

    }

  }
);


// =========================================================
// RESTABLECER CONTRASEÑA
// =========================================================

app.post(
  "/api/reset-password",
  authLimiter,
  async (req, res) => {

    try {

      const {
        token,
        password
      } = req.body;


      if (
        !token ||
        !password ||
        password.length < 8
      ) {

        return res.status(400).json({
          error:
            "Token o contraseña inválidos."
        });

      }


      const tokenHash =
        crypto.createHash(
          "sha256"
        )
        .update(token)
        .digest("hex");


      const [rows] =
        await pool.query(
          `
          SELECT *
          FROM password_resets
          WHERE token_hash=?
          AND used=0
          AND expires_at > NOW()
          LIMIT 1
          `,
          [
            tokenHash
          ]
        );


      if (!rows.length) {

        return res.status(400).json({
          error:
            "El enlace no es válido o ya venció."
        });

      }


      const hash =
        await bcrypt.hash(
          password,
          12
        );


      await pool.query(
        `
        UPDATE users
        SET password_hash=?
        WHERE id=?
        `,
        [
          hash,
          rows[0].user_id
        ]
      );


      await pool.query(
        `
        UPDATE password_resets
        SET used=1
        WHERE id=?
        `,
        [
          rows[0].id
        ]
      );


      res.json({

        ok: true,

        message:
          "Contraseña actualizada correctamente."

      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo cambiar la contraseña."

      });

    }

  }
);

// ========================================
// SOLICITUDES DE PRESUPUESTO - PÚBLICA
// ========================================

app.post("/api/quote-requests", async (req, res) => {
  try {
    const {
      name,
      phone,
      email,
      service,
      description,
      preferred_date
    } = req.body;

    // Validaciones básicas
    if (!name || !phone || !description) {
      return res.status(400).json({
        error: "Completá nombre, teléfono y descripción."
      });
    }

    // Limitar tamaño de los datos
    if (
      name.length > 150 ||
      phone.length > 50 ||
      (email && email.length > 150) ||
      (service && service.length > 150) ||
      description.length > 2000
    ) {
      return res.status(400).json({
        error: "Uno de los campos supera el límite permitido."
      });
    }

    const [result] = await pool.query(
      `
      INSERT INTO quote_requests
      (
        name,
        phone,
        email,
        service,
        description,
        preferred_date
      )
      VALUES (?, ?, ?, ?, ?, ?)
      `,
      [
        name.trim(),
        phone.trim(),
        email ? email.trim() : null,
        service ? service.trim() : null,
        description.trim(),
        preferred_date || null
      ]
    );

    res.status(201).json({
      success: true,
      message: "Solicitud enviada correctamente.",
      id: result.insertId
    });

  } catch (error) {

    console.error(
      "Error guardando solicitud de presupuesto:",
      error
    );

    res.status(500).json({
      error: "No se pudo enviar la solicitud."
    });
  }
});
// =========================================================
// GALERÍA PÚBLICA
// =========================================================

app.get(
  "/api/gallery",
  async (req, res) => {

    try {

      const [rows] =
        await pool.query(`
          SELECT
            id,
            title,
            description,
            image_url
          FROM gallery
          WHERE active = 1
          ORDER BY created_at DESC
        `);


      res.json(rows);


    } catch (e) {

      console.error(
        "Error obteniendo galería pública:",
        e
      );


      res.status(500).json({

        error:
          "No se pudieron cargar los trabajos."

      });

    }

  }
);


// =========================================================
// ADMIN - GALERÍA
// =========================================================

app.get(
  "/api/admin/gallery",
  requireAdmin,
  async (req, res) => {

    try {

      const [rows] =
        await pool.query(`
          SELECT
            id,
            title,
            description,
            image_url,
            active,
            created_at
          FROM gallery
          ORDER BY created_at DESC
        `);


      res.json(rows);


    } catch (e) {

      console.error(
        "Error obteniendo galería admin:",
        e
      );


      res.status(500).json({

        error:
          "No se pudieron cargar los trabajos."

      });

    }

  }
);


// =========================================================
// AGREGAR TRABAJO
// =========================================================

app.post(
  "/api/admin/gallery",
  requireAdmin,
  upload.single("image"),
  async (req, res) => {

    try {

      const title =
        String(
          req.body.title || ""
        ).trim();


      const description =
        String(
          req.body.description || ""
        ).trim();


      const active =
        req.body.active === "true" ||
        req.body.active === "1"
          ? 1
          : 0;


      if (!title) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(400).json({

          error:
            "El título es obligatorio."

        });

      }


      if (title.length > 150) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(400).json({

          error:
            "El título es demasiado largo."

        });

      }


      if (description.length > 500) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(400).json({

          error:
            "La descripción es demasiado larga."

        });

      }


      if (!req.file) {

        return res.status(400).json({

          error:
            "Debes seleccionar una imagen."

        });

      }


      const imageUrl =
        "/uploads/" +
        req.file.filename;


      await pool.query(
        `
        INSERT INTO gallery
        (
          title,
          description,
          image_url,
          active
        )
        VALUES
        (
          ?,
          ?,
          ?,
          ?
        )
        `,
        [
          title,
          description,
          imageUrl,
          active
        ]
      );


      res.json({

        ok: true,

        message:
          "Trabajo agregado correctamente.",

        image_url:
          imageUrl

      });


    } catch (e) {

      if (req.file) {

        try {

          fs.unlinkSync(
            req.file.path
          );

        } catch {}

      }


      console.error(
        "Error agregando trabajo:",
        e
      );


      res.status(500).json({

        error:
          "No se pudo agregar el trabajo."

      });

    }

  }
);


// =========================================================
// EDITAR TRABAJO
// =========================================================

app.put(
  "/api/admin/gallery/:id",
  requireAdmin,
  upload.single("image"),
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (!Number.isInteger(id)) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(400).json({

          error:
            "ID inválido."

        });

      }


      const title =
        String(
          req.body.title || ""
        ).trim();


      const description =
        String(
          req.body.description || ""
        ).trim();


      const active =
        req.body.active === "true" ||
        req.body.active === "1"
          ? 1
          : 0;


      if (!title) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(400).json({

          error:
            "El título es obligatorio."

        });

      }


      if (title.length > 150) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(400).json({

          error:
            "El título es demasiado largo."

        });

      }


      if (description.length > 500) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(400).json({

          error:
            "La descripción es demasiado larga."

        });

      }


      const [rows] =
        await pool.query(
          `
          SELECT
            image_url
          FROM gallery
          WHERE id=?
          LIMIT 1
          `,
          [
            id
          ]
        );


      if (!rows.length) {

        if (req.file) {

          fs.unlinkSync(
            req.file.path
          );

        }


        return res.status(404).json({

          error:
            "Trabajo no encontrado."

        });

      }


      let imageUrl =
        rows[0].image_url;


      if (req.file) {

        imageUrl =
          "/uploads/" +
          req.file.filename;

      }


      await pool.query(
        `
        UPDATE gallery
        SET
          title=?,
          description=?,
          image_url=?,
          active=?
        WHERE id=?
        `,
        [
          title,
          description,
          imageUrl,
          active,
          id
        ]
      );


      if (
        req.file &&
        rows[0].image_url
      ) {

        const oldFile =
          path.join(
            __dirname,
            "public",
            rows[0].image_url
              .replace(/^\/+/, "")
          );


        if (fs.existsSync(oldFile)) {

          try {

            fs.unlinkSync(
              oldFile
            );

          } catch (err) {

            console.error(
              "No se pudo eliminar imagen anterior:",
              err.message
            );

          }

        }

      }


      res.json({

        ok: true,

        message:
          "Trabajo actualizado correctamente."

      });


    } catch (e) {

      if (req.file) {

        try {

          fs.unlinkSync(
            req.file.path
          );

        } catch {}

      }


      console.error(
        "Error editando trabajo:",
        e
      );


      res.status(500).json({

        error:
          "No se pudo actualizar el trabajo."

      });

    }

  }
);


// =========================================================
// ELIMINAR TRABAJO
// =========================================================

app.delete(
  "/api/admin/gallery/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const id =
        Number(
          req.params.id
        );


      if (!Number.isInteger(id)) {

        return res.status(400).json({

          error:
            "ID inválido."

        });

      }


      const [rows] =
        await pool.query(
          `
          SELECT
            image_url
          FROM gallery
          WHERE id=?
          LIMIT 1
          `,
          [
            id
          ]
        );


      if (!rows.length) {

        return res.status(404).json({

          error:
            "Trabajo no encontrado."

        });

      }


      await pool.query(
        `
        DELETE FROM gallery
        WHERE id=?
        `,
        [
          id
        ]
      );


      if (rows[0].image_url) {

        const imageFile =
          path.join(
            __dirname,
            "public",
            rows[0].image_url
              .replace(/^\/+/, "")
          );


        if (fs.existsSync(imageFile)) {

          try {

            fs.unlinkSync(
              imageFile
            );

          } catch (err) {

            console.error(
              "No se pudo eliminar imagen:",
              err.message
            );

          }

        }

      }


      res.json({

        ok: true,

        message:
          "Trabajo eliminado correctamente."

      });


    } catch (e) {

      console.error(
        "Error eliminando trabajo:",
        e
      );


      res.status(500).json({

        error:
          "No se pudo eliminar el trabajo."

      });

    }

  }
);


// =========================================================
// SERVICIOS PÚBLICOS
// =========================================================

app.get(
  "/api/services",
  async (req, res) => {

    try {

      const [rows] =
        await pool.query(
          `
          SELECT
            id,
            title,
            description,
            price
          FROM services
          WHERE active=1
          ORDER BY id DESC
          `
        );


      res.json(rows);


    } catch (e) {

      console.error(
        "Error obteniendo servicios:",
        e
      );


      res.status(500).json({

        error:
          "No se pudieron cargar los servicios."

      });

    }

  }
);


// =========================================================
// ADMIN - USUARIOS
// =========================================================

app.get(
  "/api/admin/users",
  requireAdmin,
  async (req, res) => {

    try {

      const [rows] =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            role,
            created_at
          FROM users
          ORDER BY created_at DESC
          `
        );


      res.json(rows);


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudieron cargar los usuarios."

      });

    }

  }
);


// =========================================================
// ADMIN - ESTADÍSTICAS
// =========================================================

app.get(
  "/api/admin/stats",
  requireAdmin,
  async (req, res) => {

    try {

      const [[users]] =
        await pool.query(
          `
          SELECT
            COUNT(*) AS total
          FROM users
          `
        );


      const [[services]] =
        await pool.query(
          `
          SELECT
            COUNT(*) AS total
          FROM services
          `
        );


      const [[activeServices]] =
        await pool.query(
          `
          SELECT
            COUNT(*) AS total
          FROM services
          WHERE active=1
          `
        );


      res.json({

        users:
          Number(
            users.total
          ),

        services:
          Number(
            services.total
          ),

        activeServices:
          Number(
            activeServices.total
          )

      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudieron obtener las estadísticas."

      });

    }

  }
);


// =========================================================
// ADMIN - SERVICIOS
// =========================================================

app.get(
  "/api/admin/services",
  requireAdmin,
  async (req, res) => {

    try {

      const [rows] =
        await pool.query(
          `
          SELECT
            id,
            title,
            description,
            price,
            active
          FROM services
          ORDER BY id DESC
          `
        );


      res.json(rows);


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudieron cargar los servicios."

      });

    }

  }
);


app.post(
  "/api/admin/services",
  requireAdmin,
  async (req, res) => {

    try {

      const title =
        String(
          req.body.title || ""
        ).trim();


      const description =
        String(
          req.body.description || ""
        ).trim();


      const rawPrice =
        req.body.price;


      const price =
        rawPrice === "" ||
        rawPrice === null ||
        rawPrice === undefined
          ? null
          : Number(rawPrice);


      if (!title) {

        return res.status(400).json({

          error:
            "El título es obligatorio."

        });

      }


      if (title.length > 120) {

        return res.status(400).json({

          error:
            "El título es demasiado largo."

        });

      }


      if (description.length > 1000) {

        return res.status(400).json({

          error:
            "La descripción es demasiado larga."

        });

      }


      if (
        price !== null &&
        (
          !Number.isFinite(price) ||
          price < 0
        )
      ) {

        return res.status(400).json({

          error:
            "El precio no es válido."

        });

      }


      await pool.query(
        `
        INSERT INTO services
        (
          title,
          description,
          price
        )
        VALUES
        (
          ?,
          ?,
          ?
        )
        `,
        [
          title,
          description,
          price
        ]
      );


      res.json({
        ok: true
      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo crear el servicio."

      });

    }

  }
);


app.put(
  "/api/admin/services/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const title =
        String(
          req.body.title || ""
        ).trim();


      const description =
        String(
          req.body.description || ""
        ).trim();


      const rawPrice =
        req.body.price;


      const price =
        rawPrice === "" ||
        rawPrice === null ||
        rawPrice === undefined
          ? null
          : Number(rawPrice);


      const active =
        req.body.active
          ? 1
          : 0;


      if (!title) {

        return res.status(400).json({

          error:
            "El título es obligatorio."

        });

      }


      if (title.length > 120) {

        return res.status(400).json({

          error:
            "El título es demasiado largo."

        });

      }


      if (description.length > 1000) {

        return res.status(400).json({

          error:
            "La descripción es demasiado larga."

        });

      }


      if (
        price !== null &&
        (
          !Number.isFinite(price) ||
          price < 0
        )
      ) {

        return res.status(400).json({

          error:
            "El precio no es válido."

        });

      }


      const [result] =
        await pool.query(
          `
          UPDATE services
          SET
            title=?,
            description=?,
            price=?,
            active=?
          WHERE id=?
          `,
          [
            title,
            description,
            price,
            active,
            req.params.id
          ]
        );


      if (!result.affectedRows) {

        return res.status(404).json({

          error:
            "Servicio no encontrado."

        });

      }


      res.json({
        ok: true
      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo actualizar el servicio."

      });

    }

  }
);


app.delete(
  "/api/admin/services/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const [result] =
        await pool.query(
          `
          DELETE FROM services
          WHERE id=?
          `,
          [
            req.params.id
          ]
        );


      if (!result.affectedRows) {

        return res.status(404).json({

          error:
            "Servicio no encontrado."

        });

      }


      res.json({
        ok: true
      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo eliminar el servicio."

      });

    }

  }
);


// =========================================================
// ADMIN - CAMBIAR ROL
// =========================================================

app.put(
  "/api/admin/users/:id/role",
  requireAdmin,
  async (req, res) => {

    try {

      const role =
        req.body.role;


      if (
        !["user", "admin"]
          .includes(role)
      ) {

        return res.status(400).json({

          error:
            "Rol inválido."

        });

      }


      if (
        Number(
          req.params.id
        ) ===
        Number(
          req.session.user.id
        ) &&
        role !== "admin"
      ) {

        return res.status(400).json({

          error:
            "No puedes quitarte tu propio rol de administrador."

        });

      }


      const [result] =
        await pool.query(
          `
          UPDATE users
          SET role=?
          WHERE id=?
          `,
          [
            role,
            req.params.id
          ]
        );


      if (!result.affectedRows) {

        return res.status(404).json({

          error:
            "Usuario no encontrado."

        });

      }


      res.json({
        ok: true
      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo cambiar el rol."

      });

    }

  }
);


// =========================================================
// ADMIN - ELIMINAR USUARIO
// =========================================================

app.delete(
  "/api/admin/users/:id",
  requireAdmin,
  async (req, res) => {

    try {

      if (
        Number(
          req.params.id
        ) ===
        Number(
          req.session.user.id
        )
      ) {

        return res.status(400).json({

          error:
            "No puedes eliminar tu propia cuenta desde el panel."

        });

      }


      const [result] =
        await pool.query(
          `
          DELETE FROM users
          WHERE id=?
          `,
          [
            req.params.id
          ]
        );


      if (!result.affectedRows) {

        return res.status(404).json({

          error:
            "Usuario no encontrado."

        });

      }


      res.json({
        ok: true
      });


    } catch (e) {

      console.error(e);

      res.status(500).json({

        error:
          "No se pudo eliminar el usuario."

      });

    }

  }
);


// =========================================================
// PANEL DE ADMINISTRACIÓN
// =========================================================

app.get(
  "/admin",
  requireAdmin,
  (req, res) => {

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "admin.html"
      )
    );

  }
);


// =========================================================
// MANEJO DE ERRORES DE MULTER
// =========================================================

app.use(
  (err, req, res, next) => {

    if (
      err instanceof
      multer.MulterError
    ) {

      if (
        err.code ===
        "LIMIT_FILE_SIZE"
      ) {

        return res.status(400).json({

          error:
            "La imagen no puede superar los 5 MB."

        });

      }


      return res.status(400).json({

        error:
          "Error al subir la imagen."

      });

    }


    if (err) {

      console.error(err);


      return res.status(400).json({

        error:
          err.message ||
          "Error al procesar la solicitud."

      });

    }


    next();

  }
);


// =========================================================
// INICIAR SERVIDOR
// =========================================================

async function start() {

  try {

    await pool.query(
      "SELECT 1"
    );


    console.log(
      "✅ MySQL conectado"
    );
app.get("/presupuesto/:token", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "presupuesto.html")
  );
});

    app.listen(
      PORT,
      () => {

        console.log(
          `⚡ JR Electricidad: http://localhost:${PORT}`
        );

      }
    );


  } catch (e) {

    console.error(
      "❌ No se pudo conectar a MySQL:",
      e.message
    );


    process.exit(1);

  }

}
// ================================
// ADMIN
// ================================
// ========================================
// PRESUPUESTOS - ADMIN
// ========================================

// Obtener todas las solicitudes de presupuesto
app.get(
  "/api/admin/quote-requests",
  requireAdmin,
  async (req, res) => {

    try {

      const [rows] = await pool.query(`
        SELECT
          id,
          name,
          phone,
          email,
          service,
          description,
          preferred_date,
          status,
          created_at
        FROM quote_requests
        ORDER BY created_at DESC
      `);

      res.json(rows);

    } catch (error) {

      console.error(
        "Error obteniendo solicitudes:",
        error
      );

      res.status(500).json({
        error: "No se pudieron obtener las solicitudes."
      });

    }
  }
);


// Obtener una solicitud específica
app.get(
  "/api/admin/quote-requests/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const [rows] = await pool.query(
        `
        SELECT
          id,
          name,
          phone,
          email,
          service,
          description,
          preferred_date,
          status,
          created_at
        FROM quote_requests
        WHERE id = ?
        `,
        [req.params.id]
      );

      if (!rows.length) {

        return res.status(404).json({
          error: "Solicitud no encontrada."
        });

      }

      res.json(rows[0]);

    } catch (error) {

      console.error(
        "Error obteniendo solicitud:",
        error
      );

      res.status(500).json({
        error: "No se pudo obtener la solicitud."
      });

    }
  }
);


// =========================================================
// PRESUPUESTOS - UTILIDADES
// =========================================================

function quoteMoney(value) {
  return new Intl.NumberFormat("es-AR", {
    style: "currency",
    currency: "ARS",
    maximumFractionDigits: 2
  }).format(Number(value || 0));
}


function cleanQuoteItems(items) {
  if (!Array.isArray(items) || !items.length) {
    throw new Error(
      "El presupuesto debe tener al menos un concepto."
    );
  }

  return items.map(item => {
    const description = String(
      item.description || ""
    ).trim();

    const quantity = Number(item.quantity);
    const unitPrice = Number(item.unit_price);

    if (!description) {
      throw new Error(
        "Todos los conceptos deben tener una descripción."
      );
    }

    if (
      !Number.isFinite(quantity) ||
      quantity < 0 ||
      !Number.isFinite(unitPrice) ||
      unitPrice < 0
    ) {
      throw new Error(
        "Las cantidades y precios deben ser valores válidos."
      );
    }

    return {
      description,
      quantity,
      unit:
        String(item.unit || "unidad").trim() ||
        "unidad",
      unit_price: unitPrice,
      total: quantity * unitPrice
    };
  });
}


// =========================================================
// OBTENER DETALLE DEL PRESUPUESTO
// =========================================================

async function getQuoteDetail(db, id) {

  // Permite usar:
  // getQuoteDetail(pool, id)
  // getQuoteDetail(connection, id)

  const [rows] = await db.query(
    `
    SELECT
      q.id,
      q.quote_request_id,
      q.quote_number,
      q.access_token,
      q.issue_date,
      q.expiration_date,
      q.notes,
      q.status,
      q.subtotal,
      q.discount,
      q.total,
      q.pdf_filename,
      q.created_at,

      qr.name,
      qr.phone,
      qr.email,
      qr.service,
      qr.description,
      qr.preferred_date,
      qr.image_url

    FROM quotes q

    INNER JOIN quote_requests qr
      ON qr.id = q.quote_request_id

    WHERE q.id = ?

    LIMIT 1
    `,
    [id]
  );

  if (!rows.length) {
    return null;
  }

  const quote = rows[0];

  const [items] = await db.query(
    `
    SELECT
      id,
      quote_id,
      description,
      quantity,
      unit,
      unit_price,
      total

    FROM quote_items

    WHERE quote_id = ?

    ORDER BY id ASC
    `,
    [id]
  );

  quote.items = items;

  return quote;
}


// =========================================================
// GENERAR PDF
// =========================================================

function buildQuotePdf(quote) {

  const doc = new PDFDocument({
    size: "A4",
    margin: 40
  });

  const money = value =>
    `$ ${Number(value || 0).toLocaleString("es-AR", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    })}`;


  // -------------------------------------------------------
  // FECHA
  // YYYY-MM-DD → DD/MM/AAAA
  // -------------------------------------------------------

  function formatDate(value) {

    if (!value) {
      return "-";
    }

    const text = String(value)
      .substring(0, 10);

    const parts = text.split("-");

    if (parts.length === 3) {

      return `${parts[2]}/${parts[1]}/${parts[0]}`;

    }

    return text;
  }


  const pageWidth = doc.page.width;

  const left = 40;

  const right = pageWidth - 40;

  const width = right - left;


   // =========================================================
  // ENCABEZADO
  // =========================================================

  doc
    .rect(0, 0, pageWidth, 65)
    .fill("#11151c");

  // Símbolo eléctrico compatible con PDFKit
  doc
    .fillColor("#ffc400")
    .font("Helvetica-Bold")
    .fontSize(19)
    .text(
      "JR ELECTRICIDAD",
      left + 28,
      25
    );

  // Rayo dibujado
  doc
    .fillColor("#ffc400")
    .moveTo(left + 8, 25)
    .lineTo(left + 18, 25)
    .lineTo(left + 12, 36)
    .lineTo(left + 20, 36)
    .lineTo(left + 5, 55)
    .lineTo(left + 9, 41)
    .lineTo(left + 2, 41)
    .closePath()
    .fill();

  doc
    .fillColor("#ffffff")
    .font("Helvetica")
    .fontSize(7.5)
    .text(
      "Presupuesto de trabajos eléctricos",
      left + 28,
      49
    );

  // Número y fecha
  doc
    .fillColor("#ffffff")
    .font("Helvetica-Bold")
    .fontSize(8)
    .text(
      quote.quote_number,
      pageWidth - 130,
      25,
      {
        width: 85,
        align: "right"
      }
    );

  function headerDate(value) {
    if (!value) return "-";

    if (value instanceof Date) {
      const day = String(value.getUTCDate()).padStart(2, "0");
      const month = String(value.getUTCMonth() + 1).padStart(2, "0");
      const year = value.getUTCFullYear();

      return `${day}/${month}/${year}`;
    }

    const text = String(value).trim().slice(0, 10);
    const match = text.match(/^(\d{4})-(\d{2})-(\d{2})$/);

    if (match) {
      return `${match[3]}/${match[2]}/${match[1]}`;
    }

    return text;
  }

  doc
    .fillColor("#ffc400")
    .font("Helvetica")
    .fontSize(7)
    .text(
      `Generado: ${headerDate(quote.issue_date)}`,
      pageWidth - 160,
      43,
      {
        width: 115,
        align: "right"
      }
    );


  // =======================================================
  // INFORMACIÓN DEL CLIENTE
  // MUCHO MÁS COMPACTA
  // =======================================================

  let y = 75;


  doc
    .fillColor("#8c939e")
    .font("Helvetica-Bold")
    .fontSize(5.5)
    .text(
      "CLIENTE",
      left,
      y
    );


  y += 10;


  doc
    .fillColor("#11151c")
    .font("Helvetica-Bold")
    .fontSize(10)
    .text(
      quote.name || "-",
      left,
      y
    );


  y += 13;


  doc
    .fillColor("#555d68")
    .font("Helvetica")
    .fontSize(6.5)
    .text(
      `${quote.phone || "-"}   •   ${quote.email || "-"}`,
      left,
      y,
      {
        width: width
      }
    );


  // =======================================================
  // DATOS DEL PRESUPUESTO
  // =======================================================

  y += 18;


  const boxH = 35;

  const gap = 7;

  const boxW =
    (width - gap * 2) / 3;


  const info = [

    [
      "SERVICIO",
      quote.service || "-"
    ],

    [
      "FECHA EMISIÓN",
      formatDate(quote.issue_date)
    ],

    [
      "VENCIMIENTO",
      formatDate(quote.expiration_date)
    ]

  ];


  info.forEach((item, index) => {

    const x =
      left + index * (boxW + gap);


    doc
      .roundedRect(
        x,
        y,
        boxW,
        boxH,
        5
      )
      .fill("#f4f5f7");


    doc
      .fillColor("#8a919b")
      .font("Helvetica-Bold")
      .fontSize(5)
      .text(
        item[0],
        x + 8,
        y + 6
      );


    doc
      .fillColor("#161a20")
      .font("Helvetica-Bold")
      .fontSize(7)
      .text(
        item[1],
        x + 8,
        y + 17,
        {
          width: boxW - 16,
          ellipsis: true
        }
      );

  });


  y += boxH + 17;


  // =======================================================
  // DETALLE
  // =======================================================

  doc
    .fillColor("#11151c")
    .font("Helvetica-Bold")
    .fontSize(8.5)
    .text(
      "DETALLE DEL PRESUPUESTO",
      left,
      y
    );


  y += 15;


  const descX = left;

  const qtyX = 315;

  const priceX = 375;

  const totalX = 455;


  doc
    .rect(
      left,
      y,
      width,
      19
    )
    .fill("#11151c");


  doc
    .fillColor("#ffffff")
    .font("Helvetica-Bold")
    .fontSize(6)
    .text(
      "CONCEPTO",
      descX + 8,
      y + 6
    )
    .text(
      "CANT.",
      qtyX,
      y + 6,
      {
        width: 40,
        align: "center"
      }
    )
    .text(
      "PRECIO",
      priceX,
      y + 6,
      {
        width: 65,
        align: "right"
      }
    )
    .text(
      "TOTAL",
      totalX,
      y + 6,
      {
        width: 70,
        align: "right"
      }
    );


  y += 19;


  const items =
    quote.items || [];


  items.forEach((item, index) => {

    const rowH = 25;


    if (index % 2 === 0) {

      doc
        .rect(
          left,
          y,
          width,
          rowH
        )
        .fill("#f7f8fa");

    }


    doc
      .fillColor("#20252c")
      .font("Helvetica")
      .fontSize(6.5)
      .text(
        item.description || "-",
        descX + 8,
        y + 8,
        {
          width: 250
        }
      );


    doc
      .text(
        `${Number(item.quantity || 0)} ${item.unit || ""}`,
        qtyX,
        y + 8,
        {
          width: 40,
          align: "center"
        }
      );


    doc
      .text(
        money(item.unit_price),
        priceX,
        y + 8,
        {
          width: 65,
          align: "right"
        }
      );


    doc
      .font("Helvetica-Bold")
      .text(
        money(item.total),
        totalX,
        y + 8,
        {
          width: 70,
          align: "right"
        }
      );


    y += rowH;

  });


  // =======================================================
  // TOTALES
  // =======================================================

  y += 10;


  const totalsX = 360;


  doc
    .fillColor("#666d77")
    .font("Helvetica")
    .fontSize(6.5)
    .text(
      "Subtotal",
      totalsX,
      y
    );


  doc
    .fillColor("#22272e")
    .font("Helvetica-Bold")
    .text(
      money(quote.subtotal),
      totalX,
      y,
      {
        width: 70,
        align: "right"
      }
    );


  y += 14;


  if (
    Number(quote.discount || 0) > 0
  ) {

    doc
      .fillColor("#666d77")
      .font("Helvetica")
      .text(
        "Descuento",
        totalsX,
        y
      );


    doc
      .fillColor("#22272e")
      .font("Helvetica-Bold")
      .text(
        `- ${money(quote.discount)}`,
        totalX,
        y,
        {
          width: 70,
          align: "right"
        }
      );


    y += 14;

  }


  doc
    .roundedRect(
      totalsX - 10,
      y,
      width - (totalsX - left) + 10,
      32,
      6
    )
    .fill("#11151c");


  doc
    .fillColor("#ffc400")
    .font("Helvetica-Bold")
    .fontSize(7.5)
    .text(
      "TOTAL",
      totalsX,
      y + 11
    );


  doc
    .fillColor("#ffc400")
    .fontSize(12)
    .text(
      money(quote.total),
      totalX - 5,
      y + 8,
      {
        width: 75,
        align: "right"
      }
    );


  y += 46;


  // =======================================================
  // NOTAS
  // =======================================================

  if (quote.notes) {

    doc
      .fillColor("#11151c")
      .font("Helvetica-Bold")
      .fontSize(7.5)
      .text(
        "NOTAS",
        left,
        y
      );


    y += 12;


    doc
      .fillColor("#555d68")
      .font("Helvetica")
      .fontSize(6.5)
      .text(
        quote.notes,
        left,
        y,
        {
          width: width
        }
      );

  }


  // =======================================================
  // PIE
  // =======================================================

  const bottom =
    doc.page.height - 55;


  doc
    .moveTo(
      left,
      bottom - 8
    )
    .lineTo(
      right,
      bottom - 8
    )
    .strokeColor("#e1e4e8")
    .stroke();


  doc
    .fillColor("#8a919b")
    .font("Helvetica")
    .fontSize(6)
    .text(
      "JR Electricidad • Presupuesto sujeto a las condiciones acordadas",
      left,
      bottom,
      {
        width: width,
        align: "center"
      }
    );


  return doc;
}


// =========================================================
// CONVERTIR PDF A BUFFER
// =========================================================

function pdfToBuffer(doc) {

  return new Promise((resolve, reject) => {

    const chunks = [];


    doc.on("data", chunk => {
      chunks.push(chunk);
    });


    doc.on("end", () => {

      resolve(
        Buffer.concat(chunks)
      );

    });


    doc.on("error", error => {
      reject(error);
    });


    doc.end();

  });

}


// =========================================================
// PRESUPUESTOS - ADMIN
// =========================================================


// ---------------------------------------------------------
// LISTAR PRESUPUESTOS
// ---------------------------------------------------------

app.get(
  "/api/admin/quotes",
  requireAdmin,
  async (req, res) => {

    try {

      const [rows] =
        await pool.query(
          `
          SELECT
            q.id,
            q.quote_number,
			q.access_token,
            q.issue_date,
            q.expiration_date,
            q.subtotal,
            q.discount,
            q.total,
            q.status,
            q.created_at,

            qr.id AS quote_request_id,
            qr.name AS client_name,
            qr.email AS client_email,
            qr.phone AS client_phone,
            qr.service AS requested_service,

            COUNT(qi.id) AS items_count

          FROM quotes q

          INNER JOIN quote_requests qr
            ON qr.id = q.quote_request_id

          LEFT JOIN quote_items qi
            ON qi.quote_id = q.id

          GROUP BY
            q.id,
            q.quote_number,
			q.access_token,
            q.issue_date,
            q.expiration_date,
            q.subtotal,
            q.discount,
            q.total,
            q.status,
            q.created_at,
            qr.id,
            qr.name,
            qr.email,
            qr.phone,
            qr.service

          ORDER BY
            q.created_at DESC,
            q.id DESC
          `
        );


      res.json(rows);


    } catch (error) {

      console.error(
        "Error obteniendo presupuestos:",
        error
      );


      res.status(500).json({
        error:
          "No se pudieron obtener los presupuestos."
      });

    }

  }
);


// ---------------------------------------------------------
// OBTENER PRESUPUESTO
// ---------------------------------------------------------

app.get(
  "/api/admin/quotes/:id",
  requireAdmin,
  async (req, res) => {

    try {

      const quote =
        await getQuoteDetail(
          pool,
          req.params.id
        );


      if (!quote) {

        return res.status(404).json({
          error:
            "Presupuesto no encontrado."
        });

      }


      res.json(quote);


    } catch (error) {

      console.error(
        "Error obteniendo presupuesto:",
        error
      );


      res.status(500).json({
        error:
          "No se pudo obtener el presupuesto."
      });

    }

  }
);
app.get(
  "/api/public/quotes/:token",
  async (req, res) => {

    try {

      const [rows] = await pool.query(
        `
        SELECT
          q.id,
          q.quote_number,
          q.issue_date,
          q.expiration_date,
          q.notes,
          q.status,
          q.subtotal,
          q.discount,
          q.total,

          qr.name AS client_name,
          qr.email AS client_email,
          qr.phone AS client_phone,
          qr.service AS requested_service,

          qi.id AS item_id,
          qi.description,
          qi.quantity,
          qi.unit,
          qi.unit_price,
          qi.total AS item_total

        FROM quotes q

        INNER JOIN quote_requests qr
          ON qr.id = q.quote_request_id

        LEFT JOIN quote_items qi
          ON qi.quote_id = q.id

        WHERE q.access_token = ?

        ORDER BY qi.id ASC
        `,
        [req.params.token]
      );


      if (!rows.length) {

        return res.status(404).json({
          error:
            "Presupuesto no encontrado o enlace inválido."
        });

      }


      const quote = {
        id: rows[0].id,
        quote_number: rows[0].quote_number,
        issue_date: rows[0].issue_date,
        expiration_date: rows[0].expiration_date,
        notes: rows[0].notes,
        status: rows[0].status,

        subtotal: rows[0].subtotal,
        discount: rows[0].discount,
        total: rows[0].total,

        client_name: rows[0].client_name,
        client_email: rows[0].client_email,
        client_phone: rows[0].client_phone,
        requested_service: rows[0].requested_service,

        items: []
      };


      for (const row of rows) {

        if (row.item_id) {

          quote.items.push({
            id: row.item_id,
            description: row.description,
            quantity: row.quantity,
            unit: row.unit,
            unit_price: row.unit_price,
            total: row.item_total
          });

        }

      }


      res.json(quote);


    } catch (error) {

      console.error(
        "Error obteniendo presupuesto público:",
        error
      );


      res.status(500).json({
        error:
          "No se pudo obtener el presupuesto."
      });

    }

  }
);
app.post("/api/public/quotes/:token/accept", async (req, res) => {

  try {

    const [result] = await pool.query(
      `
      UPDATE quotes
      SET status = 'aceptado'
      WHERE access_token = ?
      AND status NOT IN ('aceptado', 'rechazado', 'cerrado')
      `,
      [req.params.token]
    );

    if (result.affectedRows === 0) {

      const [rows] = await pool.query(
        `
        SELECT status
        FROM quotes
        WHERE access_token = ?
        `,
        [req.params.token]
      );

      if (!rows.length) {
        return res.status(404).json({
          error: "Presupuesto no encontrado."
        });
      }

      if (rows[0].status === "aceptado") {
        return res.json({
          success: true,
          status: "aceptado",
          message: "El presupuesto ya fue aceptado."
        });
      }

      return res.status(400).json({
        error:
          "Este presupuesto ya no puede modificarse."
      });
    }

    res.json({
      success: true,
      status: "aceptado",
      message: "Presupuesto aceptado correctamente."
    });

  } catch (error) {

    console.error(
      "Error aceptando presupuesto:",
      error
    );

    res.status(500).json({
      error:
        "No se pudo aceptar el presupuesto."
    });

  }

});
app.post("/api/public/quotes/:token/reject", async (req, res) => {

  try {

    const [result] = await pool.query(
      `
      UPDATE quotes
      SET status = 'rechazado'
      WHERE access_token = ?
      AND status NOT IN ('aceptado', 'rechazado', 'cerrado')
      `,
      [req.params.token]
    );

    if (result.affectedRows === 0) {

      const [rows] = await pool.query(
        `
        SELECT status
        FROM quotes
        WHERE access_token = ?
        `,
        [req.params.token]
      );

      if (!rows.length) {
        return res.status(404).json({
          error: "Presupuesto no encontrado."
        });
      }

      if (rows[0].status === "rechazado") {
        return res.json({
          success: true,
          status: "rechazado",
          message: "El presupuesto ya fue rechazado."
        });
      }

      return res.status(400).json({
        error:
          "Este presupuesto ya no puede modificarse."
      });
    }

    res.json({
      success: true,
      status: "rechazado",
      message: "Presupuesto rechazado correctamente."
    });

  } catch (error) {

    console.error(
      "Error rechazando presupuesto:",
      error
    );

    res.status(500).json({
      error:
        "No se pudo rechazar el presupuesto."
    });

  }

});
// ---------------------------------------------------------
// GENERAR / VER PDF
// ---------------------------------------------------------

app.get(
  "/api/admin/quotes/:id/pdf",
  requireAdmin,
  async (req, res) => {

    try {

      const quote =
        await getQuoteDetail(
          pool,
          req.params.id
        );


      if (!quote) {

        return res.status(404).json({
          error:
            "Presupuesto no encontrado."
        });

      }


      const doc =
        buildQuotePdf(quote);


      res.setHeader(
        "Content-Type",
        "application/pdf"
      );


      res.setHeader(
        "Content-Disposition",
        `inline; filename="${quote.quote_number}.pdf"`
      );


      doc.pipe(res);

      doc.end();


    } catch (error) {

      console.error(
        "Error generando PDF:",
        error
      );


      if (!res.headersSent) {

        res.status(500).json({
          error:
            "No se pudo generar el PDF."
        });

      }

    }

  }
);


// ---------------------------------------------------------
// EDITAR PRESUPUESTO
// ---------------------------------------------------------

app.put(
  "/api/admin/quotes/:id",
  requireAdmin,
  async (req, res) => {

    const connection =
      await pool.getConnection();


    try {

      const quote =
        await getQuoteDetail(
          connection,
          req.params.id
        );


      if (!quote) {

        return res.status(404).json({
          error:
            "Presupuesto no encontrado."
        });

      }


      const items =
        cleanQuoteItems(
          req.body.items
        );


      const subtotal =
        items.reduce(
          (sum, item) =>
            sum + item.total,
          0
        );


      const discount =
        Math.max(
          0,
          Number(req.body.discount) || 0
        );


      const total =
        Math.max(
          0,
          subtotal - discount
        );


      await connection.beginTransaction();


      await connection.query(
        `
        UPDATE quotes

        SET
          issue_date = ?,
          expiration_date = ?,
          notes = ?,
          subtotal = ?,
          discount = ?,
          total = ?

        WHERE id = ?
        `,
        [
          req.body.issue_date ||
            quote.issue_date,

          req.body.expiration_date ||
            null,

          String(
            req.body.notes || ""
          ).trim() || null,

          subtotal,

          discount,

          total,

          quote.id
        ]
      );


      await connection.query(
        `
        DELETE FROM quote_items
        WHERE quote_id = ?
        `,
        [quote.id]
      );


      for (const item of items) {

        await connection.query(
          `
          INSERT INTO quote_items
          (
            quote_id,
            description,
            quantity,
            unit,
            unit_price,
            total
          )

          VALUES (?, ?, ?, ?, ?, ?)
          `,
          [
            quote.id,
            item.description,
            item.quantity,
            item.unit,
            item.unit_price,
            item.total
          ]
        );

      }


      await connection.commit();


      res.json({
        ok: true,
        subtotal,
        discount,
        total
      });


    } catch (error) {

      await connection.rollback();


      console.error(
        "Error actualizando presupuesto:",
        error
      );


      res.status(500).json({
        error:
          error.message ||
          "No se pudo actualizar el presupuesto."
      });


    } finally {

      connection.release();

    }

  }
);


// ---------------------------------------------------------
// ENVIAR PRESUPUESTO POR EMAIL
// ---------------------------------------------------------

app.post(
  "/api/admin/quotes/:id/send",
  requireAdmin,
  async (req, res) => {

    try {

      const quote =
        await getQuoteDetail(
          pool,
          req.params.id
        );


      if (!quote) {

        return res.status(404).json({
          error:
            "Presupuesto no encontrado."
        });

      }


      if (!quote.email) {

        return res.status(400).json({
          error:
            "El cliente no tiene un correo electrónico registrado."
        });

      }


      const pdfDoc =
        buildQuotePdf(quote);


      const pdfBuffer =
        await pdfToBuffer(pdfDoc);


      const transporter =
        nodemailer.createTransport({

          host:
            process.env.SMTP_HOST,

          port:
            Number(
              process.env.SMTP_PORT || 465
            ),

          secure:
            String(
              process.env.SMTP_SECURE
            ).toLowerCase() === "true",

          auth: {

            user:
              process.env.SMTP_USER,

            pass:
              process.env.SMTP_PASSWORD

          }

        });


      await transporter.sendMail({

        from:
          process.env.MAIL_FROM,

        to:
          quote.email,

        subject:
          `Presupuesto ${quote.quote_number} - JR Electricidad`,

        text:
          `Hola ${quote.name}, adjuntamos el presupuesto ${quote.quote_number}. Total: ${quoteMoney(quote.total)}.`,

        attachments: [

          {

            filename:
              `${quote.quote_number}.pdf`,

            content:
              pdfBuffer,

            contentType:
              "application/pdf"

          }

        ]

      });


      await pool.query(
        `
        UPDATE quotes

        SET status = 'enviado'

        WHERE id = ?
        `,
        [quote.id]
      );


      res.json({
        ok: true
      });


    } catch (error) {

      console.error(
        "Error enviando presupuesto:",
        error
      );


      res.status(500).json({
        error:
          "No se pudo enviar el presupuesto por correo."
      });

    }

  }
);


// ---------------------------------------------------------
// ELIMINAR PRESUPUESTO
// ---------------------------------------------------------

app.delete(
  "/api/admin/quotes/:id",
  requireAdmin,
  async (req, res) => {

    const connection =
      await pool.getConnection();


    try {

      const quote =
        await getQuoteDetail(
          connection,
          req.params.id
        );


      if (!quote) {

        return res.status(404).json({
          error:
            "Presupuesto no encontrado."
        });

      }


      await connection.beginTransaction();


      await connection.query(
        `
        DELETE FROM quotes
        WHERE id = ?
        `,
        [quote.id]
      );


      const [[remaining]] =
        await connection.query(
          `
          SELECT
            COUNT(*) AS total

          FROM quotes

          WHERE quote_request_id = ?
          `,
          [quote.quote_request_id]
        );


      if (!Number(remaining.total)) {

        await connection.query(
          `
          UPDATE quote_requests

          SET status = 'pendiente'

          WHERE id = ?
          `,
          [quote.quote_request_id]
        );

      }


      await connection.commit();


      res.json({
        ok: true
      });


    } catch (error) {

      await connection.rollback();


      console.error(
        "Error eliminando presupuesto:",
        error
      );


      res.status(500).json({
        error:
          "No se pudo eliminar el presupuesto."
      });


    } finally {

      connection.release();

    }

  }
);


// ---------------------------------------------------------
// CREAR PRESUPUESTO
// ---------------------------------------------------------

app.post(
  "/api/admin/quotes",
  requireAdmin,
  async (req, res) => {

    const connection =
      await pool.getConnection();


    try {

      const {
        quote_request_id,
        issue_date,
        expiration_date,
        notes,
        items,
        discount
      } = req.body;


      if (!quote_request_id) {

        return res.status(400).json({
          error:
            "Falta la solicitud."
        });

      }


      if (
        !Array.isArray(items) ||
        !items.length
      ) {

        return res.status(400).json({
          error:
            "El presupuesto debe tener al menos un concepto."
        });

      }


      const cleanItems =
        cleanQuoteItems(items);


      await connection.beginTransaction();


      // ---------------------------------------------------
      // VERIFICAR SOLICITUD
      // ---------------------------------------------------

      const [requestRows] =
        await connection.query(
          `
          SELECT *

          FROM quote_requests

          WHERE id = ?

          LIMIT 1
          `,
          [quote_request_id]
        );


      if (!requestRows.length) {

        await connection.rollback();


        return res.status(404).json({
          error:
            "Solicitud no encontrada."
        });

      }


      // ---------------------------------------------------
      // NÚMERO DE PRESUPUESTO
      // ---------------------------------------------------

      const [lastQuote] =
        await connection.query(
          `
          SELECT id

          FROM quotes

          ORDER BY id DESC

          LIMIT 1
          `
        );


      const nextNumber =
        lastQuote.length
          ? lastQuote[0].id + 1
          : 1;


      const quoteNumber =
        `P-${String(nextNumber).padStart(6, "0")}`;


      // ---------------------------------------------------
      // TOKEN PRIVADO
      // ---------------------------------------------------

      const accessToken =
        crypto
          .randomBytes(32)
          .toString("hex");


      // ---------------------------------------------------
      // SUBTOTAL
      // ---------------------------------------------------

      const subtotal =
        cleanItems.reduce(
          (sum, item) =>
            sum + item.total,
          0
        );


      // ---------------------------------------------------
      // DESCUENTO
      // ---------------------------------------------------

      const discountValue =
        Math.max(
          0,
          Number(discount) || 0
        );


      // ---------------------------------------------------
      // TOTAL
      // ---------------------------------------------------

      const total =
        Math.max(
          0,
          subtotal - discountValue
        );


      // ---------------------------------------------------
      // INSERTAR PRESUPUESTO
      // ---------------------------------------------------

      const [quoteResult] =
        await connection.query(
          `
          INSERT INTO quotes
          (
            quote_request_id,
            quote_number,
            access_token,
            issue_date,
            expiration_date,
            notes,
            subtotal,
            discount,
            total
          )

          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [

            quote_request_id,

            quoteNumber,

            accessToken,

            issue_date ||
              new Date()
                .toISOString()
                .slice(0, 10),

            expiration_date ||
              null,

            notes ||
              null,

            subtotal,

            discountValue,

            total

          ]
        );


      const quoteId =
        quoteResult.insertId;


      // ---------------------------------------------------
      // INSERTAR CONCEPTOS
      // ---------------------------------------------------

      for (const item of cleanItems) {

        await connection.query(
          `
          INSERT INTO quote_items
          (
            quote_id,
            description,
            quantity,
            unit,
            unit_price,
            total
          )

          VALUES (?, ?, ?, ?, ?, ?)
          `,
          [

            quoteId,

            item.description,

            item.quantity,

            item.unit,

            item.unit_price,

            item.total

          ]
        );

      }


      // ---------------------------------------------------
      // MARCAR SOLICITUD
      // ---------------------------------------------------

      await connection.query(
        `
        UPDATE quote_requests

        SET status = 'presupuestado'

        WHERE id = ?
        `,
        [quote_request_id]
      );


      await connection.commit();


      res.status(201).json({

        success: true,

        id:
          quoteId,

        quote_number:
          quoteNumber,

        access_token:
          accessToken,

        subtotal,

        discount:
          discountValue,

        total

      });


    } catch (error) {

      await connection.rollback();


      console.error(
        "Error creando presupuesto:",
        error
      );


      res.status(500).json({
        error:
          error.message ||
          "No se pudo crear el presupuesto."
      });


    } finally {

      connection.release();

    }

  }
);


// =========================================================
// INICIAR SERVIDOR
// =========================================================

if (require.main === module) {

  start();

}


// =========================================================
// EXPORTAR
// =========================================================

module.exports = {
  buildQuotePdf
};