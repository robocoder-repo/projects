
const request = require('supertest');
const app = require('../src/app');
const User = require('../src/models/user');

describe('User Routes', () => {
    let user;

    beforeAll(async () => {
        user = await User.create({
            name: 'Test User',
            email: 'test@example.com',
            password: 'password123',
            isVerified: true,
        });
    });

    afterAll(async () => {
        await User.destroy({ where: { email: 'test@example.com' } });
    });

    test('should create a new user', async () => {
        const response = await request(app)
            .post('/api/users')
            .send({
                name: 'New User',
                email: 'newuser@example.com',
                password: 'password123',
            });
        expect(response.statusCode).toBe(201);
        expect(response.body.email).toBe('newuser@example.com');
    });

    test('should get all users', async () => {
        const response = await request(app).get('/api/users');
        expect(response.statusCode).toBe(200);
        expect(response.body.length).toBeGreaterThan(0);
    });

    test('should send verification email', async () => {
        const response = await request(app)
            .post('/api/users/send-verification-email')
            .send({ email: 'test@example.com' });
        expect(response.statusCode).toBe(200);
        expect(response.body.message).toBe('Verification email sent');
    });

    test('should verify user', async () => {
        const token = user.verificationToken;
        const response = await request(app)
            .post('/api/users/verify')
            .send({ token });
        expect(response.statusCode).toBe(200);
        expect(response.body.message).toBe('Email verified successfully');
    });

    test('should initiate password reset', async () => {
        const response = await request(app)
            .post('/api/users/reset-password')
            .send({ email: 'test@example.com' });
        expect(response.statusCode).toBe(200);
        expect(response.body.message).toBe('Password reset email sent');
    });

    test('should complete password reset', async () => {
        const token = user.resetToken;
        const response = await request(app)
            .post('/api/users/reset-password/complete')
            .send({ token, newPassword: 'newpassword123' });
        expect(response.statusCode).toBe(200);
        expect(response.body.message).toBe('Password has been reset');
    });

    test('should issue refresh token', async () => {
        const response = await request(app)
            .post('/api/users/issue-refresh-token')
            .send({ email: 'test@example.com', password: 'password123' });
        expect(response.statusCode).toBe(200);
        expect(response.body.refreshToken).toBeDefined();
    });

    test('should refresh token', async () => {
        const token = user.refreshToken;
        const response = await request(app)
            .post('/api/users/refresh-token')
            .send({ token });
        expect(response.statusCode).toBe(200);
        expect(response.body.token).toBeDefined();
    });
});
