<!--  Copyright: Gianluca Costa & Andrea de Franceschi 2007-2010, http://www.xplico.org
    Version: MPL 1.1/GPL 2.0/LGPL 2.1
   -->
<div class="pols">
  <h2><?php echo __('New Case'); ?></h2>
  <br />
  <div class="search">
    <br />
    <?php echo $this->Form->create('Pol');
      if ($register == 0) {
        echo '<h2>'.__('DATA ACQUISITION').'</h2>';
        echo $this->Form->radio('Capture.Type',array(__('Uploading PCAP capture file/s'), __('Live acquisition')), array('separator' => '    ', 'legend' => false, 'default' => 0 ));
        echo "<br /><br />";
      }
      echo $this->Form->input('Pol.name',  array('maxlength'=> 50, 'size' => '50', 'label' => __('Case name')));
      echo $this->Form->input('Pol.external_ref',  array('maxlength'=> 50, 'size' => '50', 'label' => __('External reference')));
      echo '<div class="cline"> </div>';
      echo $this->Form->end(__('Create')); ?>
  </div>
</div>
