// ===================== Authorization endpoint (real redirect) =====================
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, code_challenge } = req.query;

  // Простая валидация
  if (!client_id || !redirect_uri || response_type !== 'code') {
    return res.status(400).send('Invalid authorization request');
  }

  // Генерируем тестовый код авторизации
  const code = 'goodseeds-auth-code-' + Math.random().toString(36).substring(2, 10);
  console.log(`Issued authorization code: ${code}`);

  // Редиректим обратно в ChatGPT
  const redirectUrl = `${redirect_uri}?code=${code}`;
  res.redirect(302, redirectUrl);
});

// ===================== OAuth Token Exchange =====================
app.post('/oauth/token', async (req, res) => {
  try {
    const { code, redirect_uri, code_verifier } = req.body || {};
    if (!code) {
      return res.status(400).json({ error: 'Missing authorization code' });
    }

    // Запрос к Google OAuth для обмена кода на токен
    const params = new URLSearchParams({
      code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirect_uri || 'https://chatgpt.com/connector_platform_oauth_redirect',
      grant_type: 'authorization_code',
      code_verifier: code_verifier || ''
    });

    const response = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    const data = await response.json();
    if (!response.ok) {
      console.error('Google token exchange error:', data);
      return res.status(response.status).json(data);
    }

    // Возвращаем ChatGPT структуру токена
    res.json({
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      token_type: data.token_type || 'Bearer',
      expires_in: data.expires_in
    });
  } catch (err) {
    console.error('Token exchange failed:', err);
    res.status(500).json({ error: 'Internal
