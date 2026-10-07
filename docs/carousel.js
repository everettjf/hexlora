// Localized screenshot galleries; the first screenshot is visible without JS.
const carousel = document.querySelector('.carousel');
if (carousel) {
  const slides = [...carousel.querySelectorAll('.slide')];
  const dots = carousel.querySelector('.carousel-dots');
  let current = 0;
  let timer;
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  const showSlide = index => {
    current = (index + slides.length) % slides.length;
    slides.forEach((slide, i) => {
      const active = i === current;
      slide.classList.toggle('active', active);
      slide.setAttribute('aria-hidden', String(!active));
    });
    [...dots.children].forEach((dot, i) => {
      dot.classList.toggle('active', i === current);
      dot.setAttribute('aria-selected', String(i === current));
    });
  };
  const stop = () => clearInterval(timer);
  const start = () => {
    stop();
    if (!reducedMotion.matches) timer = setInterval(() => showSlide(current + 1), 5200);
  };
  slides.forEach((_, i) => {
    const dot = document.createElement('button');
    dot.type = 'button';
    dot.role = 'tab';
    dot.setAttribute('aria-label', `${carousel.dataset.slideLabel} ${i + 1}`);
    dot.addEventListener('click', () => { showSlide(i); start(); });
    dots.append(dot);
  });
  carousel.querySelector('[data-previous]').addEventListener('click', () => { showSlide(current - 1); start(); });
  carousel.querySelector('[data-next]').addEventListener('click', () => { showSlide(current + 1); start(); });
  carousel.addEventListener('mouseenter', stop);
  carousel.addEventListener('mouseleave', start);
  carousel.addEventListener('focusin', stop);
  carousel.addEventListener('focusout', start);
  carousel.addEventListener('keydown', event => {
    if (event.key === 'ArrowLeft') showSlide(current - 1);
    if (event.key === 'ArrowRight') showSlide(current + 1);
  });
  reducedMotion.addEventListener('change', start);
  showSlide(0);
  start();
}
