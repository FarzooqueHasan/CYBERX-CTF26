document.addEventListener('DOMContentLoaded', () => {
    // 1. Reveal Hint Content via server-side fetch
    const hintTriggers = document.querySelectorAll('.hint-trigger');
    hintTriggers.forEach(trigger => {
        trigger.addEventListener('click', async () => {
            const index = trigger.getAttribute('data-hint-idx');
            const content = document.getElementById(`hint-content-${index}`);
            if (content.style.display === 'block') {
                content.style.display = 'none';
                trigger.querySelector('.hint-icon').textContent = '▶';
            } else {
                if (content.textContent.trim() === '' || content.innerHTML.trim() === '') {
                    content.innerHTML = '<p style="margin-bottom: 0; color: var(--text-muted); font-size: 0.85rem;">Fetching hint...</p>';
                    content.style.display = 'block';
                    trigger.querySelector('.hint-icon').textContent = '▼';
                    try {
                        const response = await fetch(`/level/hint/${index}`);
                        if (!response.ok) {
                            throw new Error('Failed to load hint');
                        }
                        const data = await response.json();
                        content.innerHTML = `<p style="margin-bottom: 0;">${data.hint}</p>`;
                    } catch (err) {
                        content.innerHTML = '<p style="margin-bottom: 0; color: var(--error); font-size: 0.85rem;">Error loading hint.</p>';
                    }
                } else {
                    content.style.display = 'block';
                    trigger.querySelector('.hint-icon').textContent = '▼';
                }
            }
        });
    });

    // 2. AJAX Flag Submission
    const flagForm = document.getElementById('flag-submit-form');
    if (flagForm) {
        flagForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const actionUrl = flagForm.getAttribute('action');
            const formData = new FormData(flagForm);
            
            const submitBtn = flagForm.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn.textContent;
            submitBtn.textContent = 'VALIDATING...';
            submitBtn.disabled = true;

            const responseAlert = document.getElementById('response-alert');
            if (responseAlert) {
                responseAlert.style.display = 'none';
                responseAlert.className = 'alert';
            }

            try {
                const response = await fetch(actionUrl, {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok && data.status === 'correct') {
                    responseAlert.textContent = 'FLAG CORRECT. ACCESS DECRYPTED. REDIRECTING...';
                    responseAlert.className = 'alert alert-success';
                    responseAlert.style.display = 'flex';
                    setTimeout(() => {
                        window.location.href = '/level';
                    }, 1500);
                } else if (data.status === 'cooldown') {
                    responseAlert.textContent = `RATE LIMIT EXCEEDED: ${data.message || 'Cooldown active.'}`;
                    responseAlert.className = 'alert alert-error';
                    responseAlert.style.display = 'flex';
                    submitBtn.textContent = originalBtnText;
                    submitBtn.disabled = false;
                } else {
                    responseAlert.textContent = 'DECRYPTION FAILED: Flag incorrect. Attempts counter incremented.';
                    responseAlert.className = 'alert alert-error';
                    responseAlert.style.display = 'flex';
                    submitBtn.textContent = originalBtnText;
                    submitBtn.disabled = false;
                    
                    // Reload attempts counter if visible
                    const attemptsCounter = document.getElementById('attempts-count');
                    if (attemptsCounter) {
                        let count = parseInt(attemptsCounter.textContent) || 0;
                        attemptsCounter.textContent = count + 1;
                    }
                }
            } catch (err) {
                responseAlert.textContent = 'NETWORK ERROR: Connection timed out.';
                responseAlert.className = 'alert alert-error';
                responseAlert.style.display = 'flex';
                submitBtn.textContent = originalBtnText;
                submitBtn.disabled = false;
            }
        });
    }
});
