
const cors = require('cors');
const express = require('express');

const corsMiddleware = (app) => {
  app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: false
  }));
};

const jsonMiddleware = (app) => {
  app.use(express.json());
};

const optionsMiddleware = (app) => {
  app.options('*', (req, res) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    res.sendStatus(200);
  });
};

module.exports = {
  corsMiddleware,
  jsonMiddleware,
  optionsMiddleware
};
