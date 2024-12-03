const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const studentRoutes = require('./routes/studentRoutes');
const paymentRoutes = require('./routes/paymentRoutes');
const feeRoutes = require('./routes/feeRoutes');
const userRoutes = require('./routes/userRoutes');
const db = require('./config/db'); 

dotenv.config(); 

const app = express();
const port = process.env.PORT || 3000; 




app.use(bodyParser.json());


app.use(cors());

app.use('/api', studentRoutes);
app.use('/api', paymentRoutes);
app.use('/api', feeRoutes);
app.use('/api', userRoutes);

app.get('/programs', (req, res) => {
  const sql = 'SELECT id, program_name, tuition_fee FROM programs';
  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(results);
  });
});


app.get('/expenses', (req, res) => {
  const { start_date, end_date } = req.query;
  let sql = 'SELECT * FROM expenses';
  const values = [];

  if (start_date && end_date) {
    sql += ' WHERE expense_date BETWEEN ? AND ?';
    values.push(start_date, end_date);
  }

  db.query(sql, values, (err, results) => {
    if (err) {
      console.error('Error fetching expenses:', err);
      return res.status(500).json({ error: 'Error fetching expenses' });
    }
    res.status(200).json(results);
  });
});


app.post('/courses', (req, res) => {
  const { program_name, tuition_fee } = req.body;

  if (!program_name || isNaN(tuition_fee)) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  const sql = `INSERT INTO programs (program_name, tuition_fee) VALUES (?, ?)`;
  db.query(sql, [program_name, tuition_fee], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ message: 'Program added successfully!' });
  });
});


app.post('/expenses', (req, res) => {
  const { person_name, amount, expense_date, description } = req.body;

  
  if (
    !person_name ||
    typeof person_name !== 'string' ||
    person_name.length > 100
  ) {
    return res.status(400).json({ error: 'Invalid person name' });
  }
  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: 'Amount must be a positive number' });
  }
  if (!expense_date || isNaN(Date.parse(expense_date))) {
    return res.status(400).json({ error: 'Invalid expense date' });
  }

  const sql =
    'INSERT INTO expenses (person_name, amount, expense_date, description) VALUES (?, ?, ?, ?)';
  db.query(
    sql,
    [person_name, amount, expense_date, description || ''],
    (err, results) => {
      if (err) {
        console.error('Error inserting expense:', err);
        return res.status(500).json({ error: 'Error adding expense' });
      }
      res
        .status(201)
        .json({ message: 'Expense added successfully', id: results.insertId });
    }
  );
});


app.get('/students/:id/paymentz', (req, res) => {
  const { id } = req.params;
  const query = `
        SELECT f.fee_name, p.payment_amount, p.payment_date, p.payment_method 
        FROM paymentz p 
        JOIN fees f ON p.fee_id = f.fee_id 
        WHERE p.student_id = ?`;

  db.query(query, [id], (err, results) => {
    if (err) return res.status(500).send(err);
    res.status(200).json(results);
  });
});


app.get('/students/:id/balance', (req, res) => {
  const { id } = req.params;
  const query = `
        SELECT f.fee_name, sfb.total_fee, sfb.amount_paid, sfb.balance_remaining
        FROM student_fee_balances sfb
        JOIN fees f ON sfb.fee_id = f.fee_id
        WHERE sfb.student_id = ?`;

  db.query(query, [id], (err, results) => {
    if (err) return res.status(500).send(err);
    res.status(200).json(results);
  });
});


app.get('/payments/:studentId', (req, res) => {
  const studentId = req.params.studentId; 

 
  const sql = `
    SELECT 
      pm.id,
      pm.amount_paid,
      pm.payment_date,
      pm.payment_method
    FROM 
      payments pm
    WHERE 
      pm.student_id = ${studentId};  -- Interpolated studentId
  `;

  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.status(200).json(results); 
  });
});


app.post('/students/:id/paymentz', (req, res) => {
  const { id } = req.params;
  const { fee_id, payment_amount, payment_date, payment_method } = req.body;

  const paymentQuery = `
        INSERT INTO paymentz (student_id, fee_id, payment_amount, payment_date, payment_method)
        VALUES (?, ?, ?, ?, ?)`;

  db.query(
    paymentQuery,
    [id, fee_id, payment_amount, payment_date, payment_method],
    (err) => {
      if (err) return res.status(500).send(err);

      const updateBalanceQuery = `
            UPDATE student_fee_balances 
            SET amount_paid = amount_paid + ?
            WHERE student_id = ? AND fee_id = ?`;
      db.query(updateBalanceQuery, [payment_amount, id, fee_id], (err) => {
        if (err) return res.status(500).send(err);
        res
          .status(200)
          .json({ message: 'Payment recorded and balance updated' });
      });
    }
  );
});


app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});