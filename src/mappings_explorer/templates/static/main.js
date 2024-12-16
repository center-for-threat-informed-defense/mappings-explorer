/**
* Template Name: Nova
* Updated: Aug 30 2023 with Bootstrap v5.3.1
* Template URL: https://bootstrapmade.com/nova-bootstrap-business-template/
* Author: BootstrapMade.com
* License: https://bootstrapmade.com/license/
*/
document.addEventListener('DOMContentLoaded', () => {
    "use strict";

    /**
     * Preloader
     */
    const preloader = document.querySelector('#preloader');
    if (preloader) {
      window.addEventListener('load', () => {
        preloader.remove();
      });
    }

    /**
     * Sticky header on scroll
     */
    const selectHeader = document.querySelector('header.header');
    if (selectHeader) {
      document.addEventListener('scroll', () => {
        window.scrollY > 100 ? selectHeader.classList.add('sticked') : selectHeader.classList.remove('sticked');
      });
    }
    /**
     * Sticky banner on scroll
     */
    const selectBanner = document.querySelector('div.banner');
    if (selectBanner) {
      document.addEventListener('scroll', () => {
        window.scrollY > 100 ? selectBanner.classList.add('sticked') : selectBanner.classList.remove('sticked');
      });
    }

    /**
     * Mobile nav toggle
     */
    const mobileNavShow = document.querySelector('.mobile-nav-show');
    const mobileNavHide = document.querySelector('.mobile-nav-hide');

    document.querySelectorAll('.mobile-nav-toggle').forEach(el => {
      el.addEventListener('click', function(event) {
        event.preventDefault();
        mobileNavToogle();
      })
    });

    function mobileNavToogle() {
      document.querySelector('body').classList.toggle('mobile-nav-active');
      mobileNavShow.classList.toggle('d-none');
      mobileNavHide.classList.toggle('d-none');
    }

    /**
     * Toggle mobile nav dropdowns
     */
    const navDropdowns = document.querySelectorAll('.navbar .dropdown > a');

    navDropdowns.forEach(el => {
      el.addEventListener('click', function(event) {
        if (document.querySelector('.mobile-nav-active')) {
          event.preventDefault();
          this.classList.toggle('active');
          this.nextElementSibling.classList.toggle('dropdown-active');

          let dropDownIndicator = this.querySelector('.dropdown-indicator');
          dropDownIndicator.classList.toggle('bi-chevron-up');
          dropDownIndicator.classList.toggle('bi-chevron-down');
        }
      })
    });

    /**
     * Scroll top button
     */
    const scrollTop = document.querySelector('.scroll-top');
    if (scrollTop) {
      const togglescrollTop = function() {
        window.scrollY > 100 ? scrollTop.classList.add('active') : scrollTop.classList.remove('active');
      }
      window.addEventListener('load', togglescrollTop);
      document.addEventListener('scroll', togglescrollTop);
      scrollTop.addEventListener('click', window.scrollTo({
        top: 0,
        behavior: 'smooth'
      }));
    }

    /**
     * Initiate glightbox
     */
    const glightbox = GLightbox({
      selector: '.glightbox'
    });

    /**
     * Init swiper slider with 1 slide at once in desktop view
     */
    new Swiper('.slides-1', {
      speed: 600,
      loop: true,
      autoplay: {
        delay: 5000,
        disableOnInteraction: false
      },
      slidesPerView: 'auto',
      pagination: {
        el: '.swiper-pagination',
        type: 'bullets',
        clickable: true
      },
      navigation: {
        nextEl: '.swiper-button-next',
        prevEl: '.swiper-button-prev',
      }
    });

    /**
     * Init swiper slider with 3 slides at once in desktop view
     */
    new Swiper('.slides-3', {
      speed: 600,
      loop: true,
      autoplay: {
        delay: 5000,
        disableOnInteraction: false
      },
      slidesPerView: 'auto',
      pagination: {
        el: '.swiper-pagination',
        type: 'bullets',
        clickable: true
      },
      navigation: {
        nextEl: '.swiper-button-next',
        prevEl: '.swiper-button-prev',
      },
      breakpoints: {
        320: {
          slidesPerView: 1,
          spaceBetween: 40
        },

        1200: {
          slidesPerView: 3,
        }
      }
    });

    /**
     * Porfolio isotope and filter
     */
    let portfolionIsotope = document.querySelector('.portfolio-isotope');

    if (portfolionIsotope) {

      let portfolioFilter = portfolionIsotope.getAttribute('data-portfolio-filter') ? portfolionIsotope.getAttribute('data-portfolio-filter') : '*';
      let portfolioLayout = portfolionIsotope.getAttribute('data-portfolio-layout') ? portfolionIsotope.getAttribute('data-portfolio-layout') : 'masonry';
      let portfolioSort = portfolionIsotope.getAttribute('data-portfolio-sort') ? portfolionIsotope.getAttribute('data-portfolio-sort') : 'original-order';

      window.addEventListener('load', () => {
        let portfolioIsotope = new Isotope(document.querySelector('.portfolio-container'), {
          itemSelector: '.portfolio-item',
          layoutMode: portfolioLayout,
          filter: portfolioFilter,
          sortBy: portfolioSort
        });

        let menuFilters = document.querySelectorAll('.portfolio-isotope .portfolio-flters li');
        menuFilters.forEach(function(el) {
          el.addEventListener('click', function() {
            document.querySelector('.portfolio-isotope .portfolio-flters .filter-active').classList.remove('filter-active');
            this.classList.add('filter-active');
            portfolioIsotope.arrange({
              filter: this.getAttribute('data-filter')
            });
            if (typeof aos_init === 'function') {
              aos_init();
            }
          }, false);
        });

      });

    }

    /**
     * Animation on scroll function and init
     */
    function aos_init() {
      AOS.init({
        duration: 800,
        easing: 'slide',
        once: true,
        mirror: false
      });
    }
    window.addEventListener('load', () => {
      aos_init();
    });




  });


/**
 * Opens a table's info box.
 * @remarks
 *  This function is a bit of a hack meant to work around present limitations
 *  in the chosen table library (Bootstrap).
 * @param {HTMLElement} el
 *  The invoking HTML element.
 */
function openInfoBox(el) {
  // Assign id to button if one is not already assigned
  if(!el.hasAttribute("id")) {
    const _id = crypto.randomUUID().substring(0, 8);
    el.setAttribute("id", `cell-${ _id }`);
  }
  const id = el.getAttribute("id");
  // Select <tr>
  let tr = el;
  while(tr && tr.tagName !== "TR") {
    tr = tr.parentElement;
  }
  // Select info box
  let tdInfoBox;
  let trInfoBox = tr.nextSibling;
  // If content collapsed...
  if(el.children.length === 0) {
    // Remove active class from button
    el.classList.remove("active");
    // Select info box
    if(!trInfoBox || !trInfoBox.classList.contains("info-box")) {
      throw new Error("Cannot locate info box!");
    }
    tdInfoBox = trInfoBox.children[0];
    // Select for content
    let content = tdInfoBox.children;
    for(let child of tdInfoBox.children) {
      if(child.getAttribute("id") === id) {
        content = child;
        break;
      }
    }
    if(!content) {
      throw new Error("Cannot locate content!");
    }
    // Move content back
    el.appendChild(content);
    // Destroy info box, if empty
    if(tdInfoBox.children.length === 0) {
      trInfoBox.remove();
    }
    return;
  }
  // If content un-collapsed...
  if(el.children.length === 1) {
    // Assign active class to button
    el.classList.add("active");
    // Select content
    const content = el.children[0];
    if(!content.classList.contains("info-box-content")) {
      throw new Error("Cannot locate content!");
    }
    // Apply id to content
    content.setAttribute("id", id);
    // Create info box, if none
    if(!trInfoBox || !trInfoBox.classList.contains("info-box")) {
      tdInfoBox = document.createElement("td");
      tdInfoBox.setAttribute("colspan", "100%");
      trInfoBox = document.createElement("tr");
      trInfoBox.classList.add("info-box");
      trInfoBox.appendChild(tdInfoBox);
      tr.after(trInfoBox);
    } else {
      tdInfoBox = trInfoBox.children[0];
    }
    // Insert content
    tdInfoBox.append(content);
    return;
  }
  // Otherwise...
  throw new Error("Invalid info box state!")
}
