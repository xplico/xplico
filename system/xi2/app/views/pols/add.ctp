<!--  Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
    Version: MPL 1.1/GPL 2.0/LGPL 2.1
   -->
<div class="pols">
  <h2><?php __('New Case'); ?></h2>
  <br />
  <div class="search">
    <br />
    <?php echo $form->create('Pol');
      if ($register == 0) {
        echo '<h2>'.__('DATA ACQUISITION', true).'</h2>';
        echo $form->radio('Capture.Type',array(__('Uploading PCAP capture file/s', true), __('Live acquisition', true)), array('separator' => '    ', 'legend' => false, 'default' => 0 ));
        echo "<br /><br />";
      }
      echo $form->input('Pol.name',  array('maxlength'=> 50, 'size' => '50', 'label' => __('Case name', true)));
      echo $form->input('Pol.external_ref',  array('maxlength'=> 50, 'size' => '50', 'label' => __('External reference', true)));
      echo '<div class="cline"> </div>';
      echo $form->end(__('Create', true)); ?>
  </div>
</div>
