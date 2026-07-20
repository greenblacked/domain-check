import { fireEvent, render, screen } from '@testing-library/react';
import App from './App';

describe('App', () => {
  it('explains invalid hostname input accessibly', () => {
    render(<App />);
    fireEvent.change(screen.getByLabelText('Domain hostname'), { target: { value: 'http://127.0.0.1:8080' } });
    fireEvent.click(screen.getByRole('button', { name: 'Run check' }));
    expect(screen.getByRole('alert')).toHaveTextContent('not a URL, IP address, or port');
  });
});

